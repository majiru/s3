#include <u.h>
#include <libc.h>
#include <bio.h>
#include <mp.h>
#include <libsec.h>
#include <auth.h>
#include "s3.h"

/*
 * S3 requires that all reserved characters within a query
 * are URL-encoded, despite the spec not mandating it.
 */
static int
queryvalfmt(Fmt *f)
{
	static char hex[] = "0123456789ABCDEF";
	char *s;
	int n;

	s = va_arg(f->args, char*);
	n = 0;
	while(*s != '\0'){
		switch(*s){
		case 'a'...'z':
		case 'A'...'Z':
		case '0'...'9':
			n += fmtprint(f, "%c", *s);
			break;
		default:
			n += fmtprint(f, "%%%c%c", hex[(*s)>>4], hex[(*s)&15]);
			break;
		}
		s++;
	}
	return n;
}

void
s3fmtinstall(void)
{
	fmtinstall('U', queryvalfmt);
}

typedef struct {
	uchar *payhash;
	char *mime;
	char *path;
	char *method;
	char time[128];
	char authhdr[512];
	char *range;
	long length;
} Hreq;

static void
datetime(char *date, int ndate, char *time, int ntime)
{
	Tm t;

	tmnow(&t, nil);
	snprint(date, ndate, "%τ", tmfmt(&t, "YYYYMMDD"));
	snprint(time, ntime, "%sT%τZ", date, tmfmt(&t, "hhmmss"));
}

static void
getkey(char *date, char *region, char *service, char *access, uchar out[SHA2_256dlen])
{
	int fd;
	AuthRpc *rpc;
	char buf[256];
	int n;

	fd = open("/mnt/factotum/rpc", ORDWR);
	if(fd < 0)
		sysfatal("factotum rpc open: %r");
	rpc = auth_allocrpc(fd);
	n = snprint(buf, sizeof buf, "proto=aws4 access=%s", access);
	if(auth_rpc(rpc, "start", buf, n) != ARok)
		sysfatal("auth_rpc: %r");
	n = snprint(buf, sizeof buf, "%s %s %s", date, region, service);
	if(auth_rpc(rpc, "write", buf, n) != ARok)
		sysfatal("auth_rpc: %r");
	if(auth_rpc(rpc, "read", nil, 0) != ARok)
		sysfatal("auth_rpc: %r");
	if(rpc->narg != SHA2_256dlen)
		sysfatal("invalid auth_rpc output");
	memcpy(out, rpc->arg, SHA2_256dlen);
	auth_freerpc(rpc);
	close(fd);
}

static void
mkreq(Hreq *hreq, char *method, char *path, uchar *payhash, char *mime)
{
	hreq->method = method;
	hreq->path = path;
	hreq->payhash = payhash;
	hreq->mime = mime;
	hreq->range = nil;
	hreq->length = -1;
}

static void
signreq(Hreq *hreq, S3 *s3)
{
	char date[64];
	uchar key[SHA2_256dlen], sig[SHA2_256dlen];
	char buf[1024], buf2[1024], req[1024];
	char *sgndhdr;
	char *query;

	datetime(date, sizeof date, hreq->time, sizeof hreq->time);
	if(strcmp(hreq->method, "POST") == 0){
		snprint(buf, sizeof buf, "content-type:%s\nhost:%s\nx-amz-content-sha256:%.*lH\nx-amz-date:%s\n",
			hreq->mime, s3->host, SHA2_256dlen, hreq->payhash, hreq->time);
		sgndhdr = "content-type;host;x-amz-content-sha256;x-amz-date";
	} else if(strcmp(hreq->method, "PUT") == 0){
		snprint(buf, sizeof buf, "content-type:%s\nhost:%s\nx-amz-content-sha256:%.*lH\nx-amz-date:%s\n",
			hreq->mime, s3->host, SHA2_256dlen, hreq->payhash, hreq->time);
		sgndhdr = "content-type;host;x-amz-content-sha256;x-amz-date";
	} else if(strcmp(hreq->method, "GET") == 0 || strcmp(hreq->method, "DELETE")==0 || strcmp(hreq->method, "POST") == 0){
		sha2_256(nil, 0, hreq->payhash, nil);
		snprint(buf, sizeof buf, "host:%s\nx-amz-date:%s\n", s3->host, hreq->time);
		sgndhdr = "host;x-amz-date";
	} else
		sysfatal("invalid method");

	snprint(buf2, sizeof buf2, "%s", hreq->path);
	if((query = strchr(buf2, '?')) != nil){
		*query = '\0';
		query++;
	} else
		query = "";
	snprint(req, sizeof req, "%s\n/%s/%s\n%s\n%s\n%s\n%.*lH",
		hreq->method, s3->bucket, buf2, query, buf, sgndhdr, SHA2_256dlen, hreq->payhash);
	sha2_256((uchar*)req, strlen(req), key, nil);
	snprint(buf, sizeof buf, "%s\n%s\n%s/%s/%s/aws4_request\n%.*lH",
		"AWS4-HMAC-SHA256", hreq->time, date, s3->region, "s3", SHA2_256dlen, key);
	getkey(date, s3->region, "s3", s3->access, key);
	hmac_sha2_256((uchar*)buf, strlen(buf), key, SHA2_256dlen, sig, nil);

	snprint(hreq->authhdr, sizeof hreq->authhdr, "%s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%.*lH",
		"AWS4-HMAC-SHA256", s3->access, date, s3->region, "s3", sgndhdr, SHA2_256dlen, sig);
}

/* small fprint buffers bite us */
#pragma	   varargck    argpos	   ctlprint 2
static long
ctlprint(int cfd, char *fmt, ...)
{
	char buf[2048];
	char *e;
	va_list arg;

	va_start(arg, fmt);
	e = vseprint(buf, buf + sizeof buf, fmt, arg);
	va_end(arg);
	return write(cfd, buf, e-buf);
}

static int
prep(S3 *s3, int cfd, Hreq *hreq)
{
	if(ctlprint(cfd, "url %s/%s/%s", s3->endpoint, s3->bucket, hreq->path) < 0)
		return -1;
	if(ctlprint(cfd, "request %s", hreq->method) < 0)
		return -1;
	if(ctlprint(cfd, "headers Authorization:%s", hreq->authhdr) < 0)
		return -1;
	if(ctlprint(cfd, "headers x-amz-date:%s\nx-amz-content-sha256:%.*lH", hreq->time, SHA2_256dlen, hreq->payhash) < 0)
		return -1;
	if(hreq->mime != nil && ctlprint(cfd, "contenttype %s", hreq->mime) < 0)
		return -1;
	if(hreq->range != nil && ctlprint(cfd, "headers range: %s", hreq->range) < 0)
		return -1;
	if(hreq->length != -1 && ctlprint(cfd, "headers content-length: %ld", hreq->length) < 0)
		return -1;
	return 0;
}

static int
hopen(Hcon *h, S3 *s3, int mode, Hreq *hreq)
{
	long n;
	char buf[64];

	h->body = -1;
	h->post = -1;
	h->err = -1;
	h->ctl = open("/mnt/web/clone", ORDWR);
	if(h->ctl < 0)
		return -1;

	n = read(h->ctl, h->id, sizeof h->id - 1);
	if(n <= 0){
		close(h->ctl);
		werrstr("short read from /mnt/web/clone");
		return -1;
	}
	h->id[n-1] = 0;

	signreq(hreq, s3);
	if(prep(s3, h->ctl, hreq) < 0){
		close(h->ctl);
		return -1;
	}
	switch(h->mode = mode){
	case OREAD:
		snprint(buf, sizeof buf, "/mnt/web/%s/body", h->id);
		h->body = open(buf, OREAD);
		if(h->body >= 0)
			return 0;
		snprint(buf, sizeof buf, "/mnt/web/%s/errorbody", h->id);
		h->err = open(buf, OREAD);
		return -1;
	case ORDWR:
	case OWRITE:
		snprint(buf, sizeof buf, "/mnt/web/%s/postbody", h->id);
		h->post = open(buf, OWRITE);
		return 0;
	default:
		return -1;
	}
}

void
hclose(Hcon *h)
{
	if(h->ctl >= 0)
		close(h->ctl);
	if(h->body >= 0)
		close(h->body);
	if(h->post >= 0)
		close(h->post);
	if(h->err >= 0)
		close(h->err);
}

int
hdone(Hcon *h)
{
	char buf[64];

	switch(h->mode){
	case OWRITE:
	case ORDWR:
		close(h->post);
		h->post = -1;
		snprint(buf, sizeof buf, "/mnt/web/%s/body", h->id);
		h->body = open(buf, OREAD);
		if(h->body < 0){
			snprint(buf, sizeof buf, "/mnt/web/%s/errorbody", h->id);
			h->err = open(buf, OREAD);
			return -1;
		}
		return 0;
	default:
		abort();
	}
}

int
s3get(S3 *s3, Hcon *con, char *path)
{
	Hreq h;
	uchar payhash[SHA2_256dlen];

	mkreq(&h, "GET", path, payhash, nil);
	return hopen(con, s3, OREAD, &h);
}

int
s3getrange(S3 *s3, Hcon *con, char *path, long off, long n)
{
	Hreq h;
	uchar payhash[SHA2_256dlen];
	char buf[64];

	mkreq(&h, "GET", path, payhash, nil);
	snprint(buf, sizeof buf, "bytes=%ld-%ld", off, off+n-1);
	h.range = buf;
	return hopen(con, s3, OREAD, &h);
}

int
s3put(S3 *s3, Hcon *con, char *path, char *mime, uchar *payhash, long length)
{
	Hreq h;

	mkreq(&h, "PUT", path, payhash, mime);
	h.length = length;
	return hopen(con, s3, ORDWR, &h);
}

int
s3del(S3 *s3, Hcon *con, char *path)
{
	Hreq h;
	uchar payhash[SHA2_256dlen];

	mkreq(&h, "DELETE", path, payhash, nil);
	return hopen(con, s3, OREAD, &h);
}

int
s3post(S3 *s3, Hcon *con, char *path)
{
	Hreq h;
	uchar payhash[SHA2_256dlen];

	sha2_256(nil, 0, payhash, nil);
	mkreq(&h, "POST", path, payhash, "application/octet-stream");
	if(hopen(con, s3, ORDWR, &h) < 0)
		return -1;
	
	return hdone(con);
}

int
s3postwrite(S3 *s3, Hcon *con, char *path, char *mime, uchar *payhash)
{
	Hreq h;

	mkreq(&h, "POST", path, payhash, mime);
	return hopen(con, s3, ORDWR, &h);
}
