#include <u.h>
#include <libc.h>
#include <bio.h>
#include <mp.h>
#include <libsec.h>
#include <auth.h>
#include "s3.h"

typedef struct {
	uchar *payhash;
	char *mime;
	char method[16];
	char time[128];
	char authhdr[512];
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
mkhreq(Hreq *hreq, S3 *s3, char *method, char *path)
{
	char date[64];
	uchar key[SHA2_256dlen], sig[SHA2_256dlen];
	char buf[512], req[512];
	char *sgndhdr;

	datetime(date, sizeof date, hreq->time, sizeof hreq->time);
	if(strcmp(method, "PUT") == 0){
		snprint(buf, sizeof buf, "content-type:%s\nhost:%s\nx-amz-content-sha256:%.*lH\nx-amz-date:%s\n",
			hreq->mime, s3->host, SHA2_256dlen, hreq->payhash, hreq->time);
		sgndhdr = "content-type;host;x-amz-content-sha256;x-amz-date";
	} else if(strcmp(method, "GET") == 0 || strcmp(method, "DELETE")==0){
		hreq->mime = nil;
		sha2_256(nil, 0, hreq->payhash, nil);
		snprint(buf, sizeof buf, "host:%s\nx-amz-date:%s\n", s3->host, hreq->time);
		sgndhdr = "host;x-amz-date";
	} else
		sysfatal("invalid method");

	snprint(req, sizeof req, "%s\n/%s/%s\n%s\n%s\n%s\n%.*lH",
		method, s3->bucket, path, "", buf, sgndhdr, SHA2_256dlen, hreq->payhash);
	sha2_256((uchar*)req, strlen(req), key, nil);
	snprint(buf, sizeof buf, "%s\n%s\n%s/%s/%s/aws4_request\n%.*lH",
		"AWS4-HMAC-SHA256", hreq->time, date, s3->region, "s3", SHA2_256dlen, key);
	getkey(date, s3->region, "s3", s3->access, key);
	hmac_sha2_256((uchar*)buf, strlen(buf), key, SHA2_256dlen, sig, nil);

	snprint(hreq->authhdr, sizeof hreq->authhdr, "%s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%.*lH",
		"AWS4-HMAC-SHA256", s3->access, date, s3->region, "s3", sgndhdr, SHA2_256dlen, sig);
	snprint(hreq->method, sizeof hreq->method, "%s", method);
}

static int
prep(S3 *s3, int cfd, char *path, Hreq *hreq)
{
	if(fprint(cfd, "url %s/%s/%s", s3->endpoint, s3->bucket, path) < 0)
		return -1;
	if(fprint(cfd, "request %s", hreq->method) < 0)
		return -1;
	if(fprint(cfd, "headers Authorization:%s", hreq->authhdr) < 0)
		return -1;
	if(fprint(cfd, "headers x-amz-date:%s\nx-amz-content-sha256:%.*lH", hreq->time, SHA2_256dlen, hreq->payhash) < 0)
		return -1;
	if(hreq->mime != nil && fprint(cfd, "contenttype %s", hreq->mime) < 0)
		return -1;
	return 0;
}

static int
wopen(char *buf, long n)
{
	int fd;

	fd = open("/mnt/web/clone", ORDWR);
	if(fd < 0)
		return fd;
	n = read(fd, buf, n - 1);
	if(n <= 0){
		werrstr("short read from /mnt/web/clone");
		return -1;
	}
	buf[n-1] = 0;
	return fd;
}

int
s3get(S3 *s3, char *path)
{
	char id[64];
	char body[64];
	int fd, bfd;
	Hreq h;
	uchar payhash[SHA2_256dlen];

	h.payhash = payhash;
	fd = wopen(id, sizeof id);
	if(fd < 0)
		return -1;
	mkhreq(&h, s3, "GET", path);
	if(prep(s3, fd, path, &h) < 0)
		return -1;
	snprint(body, sizeof body, "/mnt/web/%s/body", id);
	bfd = open(body, OREAD);
	close(fd);
	return bfd;
}

int
s3put(S3 *s3, char *path, char *mime, uchar *payhash)
{
	char id[64];
	char body[64];
	int fd, bfd;
	Hreq h;

	h.mime = mime;
	h.payhash = payhash;
	fd = wopen(id, sizeof id);
	if(fd < 0)
		return -1;
	mkhreq(&h, s3, "PUT", path);
	if(prep(s3, fd, path, &h) < 0)
		return -1;
	snprint(body, sizeof body, "/mnt/web/%s/postbody", id);
	bfd = open(body, OWRITE);
	close(fd);
	return bfd;
}

int
s3del(S3 *s3, char *path)
{
	char id[64];
	char body[64];
	int fd, bfd;
	Hreq h;
	uchar payhash[SHA2_256dlen];

	h.payhash = payhash;
	fd = wopen(id, sizeof id);
	if(fd < 0)
		return -1;
	mkhreq(&h, s3, "DELETE", path);
	if(prep(s3, fd, path, &h) < 0)
		return -1;
	snprint(body, sizeof body, "/mnt/web/%s/body", id);
	bfd = open(body, OREAD);
	close(fd);
	return bfd;
}
