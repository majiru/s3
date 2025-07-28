#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>

typedef struct {
	char *endpoint;
	char *host;
	char *access;
	char *secret;
	char *bucket;
	char *region;
} S3;

static void
datetime(char *date, int ndate, char *time, int ntime)
{
	Tm t;

	tmnow(&t, nil);
	snprint(date, ndate, "%τ", tmfmt(&t, "YYYYMMDD"));
	snprint(time, ntime, "%sT%τZ", date, tmfmt(&t, "hhmmss"));
}

#define hmac(data, dlen, key, klen, digest) hmac_sha2_256(data, dlen, key, klen, digest, nil)
#define hash(data, dlen, digest) sha2_256(data, dlen, digest, nil)

static void
mkkey(char *key, char *date, char *region, char *service, uchar out[SHA2_256dlen])
{
	char buf[256];

	snprint(buf, sizeof buf, "AWS4%s", key);
	hmac((uchar*)date, strlen(date), (uchar*)buf, strlen(buf), out);
	hmac((uchar*)region, strlen(region), out, SHA2_256dlen, (uchar*)buf);
	hmac((uchar*)service, strlen(service), (uchar*)buf, SHA2_256dlen, out);
	hmac((uchar*)"aws4_request", 12, out, SHA2_256dlen, out);
}

static void
prepupload(S3 *s3, int cfd, char *path, uchar hash[SHA2_256dlen], char *mime)
{
	char date[64];
	char time[128];
	uchar key[SHA2_256dlen], sig[SHA2_256dlen];
	char buf[512], req[512];

	datetime(date, sizeof date, time, sizeof time);

	snprint(buf, sizeof buf, "content-type:%s\nhost:%s\nx-amz-content-sha256:%.*lH\nx-amz-date:%s\n",
		mime, s3->host, SHA2_256dlen, hash, time);
	snprint(req, sizeof req, "PUT\n/%s/%s\n%s\n%s\n%s\n%.*lH",
		s3->bucket, path, "", buf, "content-type;host;x-amz-content-sha256;x-amz-date", SHA2_256dlen, hash);
	hash((uchar*)req, strlen(req), key);
	snprint(buf, sizeof buf, "%s\n%s\n%s/%s/%s/aws4_request\n%.*lH",
		"AWS4-HMAC-SHA256", time, date, s3->region, "s3", SHA2_256dlen, key);
	mkkey(s3->secret, date, s3->region, "s3", key);
	hmac((uchar*)buf, strlen(buf), key, SHA2_256dlen, sig);
	snprint(buf, sizeof buf, "%s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%.*lH",
		"AWS4-HMAC-SHA256", s3->access, date, s3->region, "s3", "content-type;host;x-amz-content-sha256;x-amz-date",
		SHA2_256dlen, sig);

	if(fprint(cfd, "url %s/%s/%s", s3->endpoint, s3->bucket, path) < 0)
		sysfatal("url: %r");
	if(fprint(cfd, "request PUT") < 0)
		sysfatal("request: %r");
	if(fprint(cfd, "headers Authorization:%s", buf) < 0)
		sysfatal("headers2: %r");
	if(fprint(cfd, "headers x-amz-date:%s\nx-amz-content-sha256:%.*lH", time, SHA2_256dlen, hash) < 0)
		sysfatal("headers: %r");
	if(fprint(cfd, "contenttype %s", mime) < 0)
		sysfatal("contenttype: %r");
}

static void
prepdownload(S3 *s3, int cfd, char *path)
{
	char date[64];
	char time[128];
	uchar hash[SHA2_256dlen], key[SHA2_256dlen], sig[SHA2_256dlen];
	char buf[512], req[512];

	datetime(date, sizeof date, time, sizeof time);
	hash(nil, 0, hash);

	snprint(buf, sizeof buf, "host:%s\nx-amz-date:%s\n", s3->host, time);
	snprint(req, sizeof req, "GET\n/%s/%s\n%s\n%s\n%s\n%.*lH",
		s3->bucket, path, "", buf, "host;x-amz-date", SHA2_256dlen, hash);
	hash((uchar*)req, strlen(req), key);
	snprint(buf, sizeof buf, "%s\n%s\n%s/%s/%s/aws4_request\n%.*lH",
		"AWS4-HMAC-SHA256", time, date, s3->region, "s3", SHA2_256dlen, key);
	mkkey(s3->secret, date, s3->region, "s3", key);
	hmac((uchar*)buf, strlen(buf), key, SHA2_256dlen, sig);
	snprint(buf, sizeof buf, "%s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%.*lH",
		"AWS4-HMAC-SHA256", s3->access, date, s3->region, "s3", "host;x-amz-date",
		SHA2_256dlen, sig);

	if(fprint(cfd, "url %s/%s/%s", s3->endpoint, s3->bucket, path) < 0)
		sysfatal("url: %r");
	if(fprint(cfd, "headers Authorization:%s", buf) < 0)
		sysfatal("headers2: %r");
	if(fprint(cfd, "headers x-amz-date:%s\nx-amz-content-sha256:%.*lH", time, SHA2_256dlen, hash) < 0)
		sysfatal("headers: %r");
}

static void
download(S3 *s3, char *path, char *localpath, int cfd, char *conn)
{
	int fd, bfd;
	long n;
	char buf[64];
	char data[8192];

	fd = create(localpath, OWRITE, 0644);
	if(fd < 0)
		sysfatal("download create: %r");
	prepdownload(s3, cfd, path);
	snprint(buf, sizeof buf, "/mnt/web/%s/body", conn);
	bfd = open(buf, OREAD);
	if(bfd < 0)
		sysfatal("download body: %r");
	for(;;){
		n = read(bfd, data, sizeof data);
		if(n < 0)
			sysfatal("download body: %r");
		if(n == 0)
			return;
		write(fd, data, n);
	}
}

static char*
mimetype(char *path)
{
	int p[2];
	char buf[256];
	int n;

	pipe(p);
	switch(fork()){
	case 0:
		close(0);
		dup(p[0], 1);
		close(2);
		close(p[0]);
		close(p[1]);
		execl("/bin/file", "file", "-m", path, nil);
		sysfatal("execl: %r");
	default:
		close(p[0]);
		n = read(p[1], buf, sizeof buf - 1);
		if(n <= 0)
			sysfatal("no mimetype found");
		buf[n - 1] = 0;
		return strdup(buf);
	}
}

static void
upload(S3 *s3, char *path, char *localpath, int cfd, char *conn)
{
	char *mime;
	DigestState *ds;
	uchar hash[SHA2_256dlen];
	uchar data[8192];
	long n;
	int fd, bfd;
	char buf[256];

	mime = mimetype(localpath);
	fd = open(localpath, OREAD);
	if(fd < 0)
		sysfatal("upload open: %r");
	for(ds = nil;;){
		n = read(fd, data, sizeof data);
		if(n < 0)
			sysfatal("file read: %r");
		if(n == 0)
			break;
		ds = sha2_256(data, n, nil, ds);
	}
	sha2_256(nil, 0, hash, ds);
	seek(fd, 0, 0);

	prepupload(s3, cfd, path, hash, mime);
	snprint(buf, sizeof buf, "/mnt/web/%s/postbody", conn);
	bfd = open(buf, OWRITE);
	if(bfd < 0)
		sysfatal("upload postbody open: %r");
	for(;;){
		n = read(fd, buf, sizeof buf);
		if(n < 0)
			sysfatal("file read: %r");
		if(n == 0)
			break;
		if(write(bfd, buf, n) < 0)
			sysfatal("upload write: %r");
	}
	close(bfd);

	snprint(buf, sizeof buf, "/mnt/web/%s/body", conn);
	if((bfd = open(buf, OREAD)) < 0)
		sysfatal("open3: %r");
	close(bfd);
}

_Noreturn static void
usage(void)
{
	fprint(2, "Requires $AWS_ACCESS_KEY_ID, $AWS_SECRET_ACCESS_KEY, and $AWS_ENDPOINT_URL_S3 defined\n");
	fprint(2, "Usage: %s source s3://<bucket>/destination\n", argv0);
	fprint(2, "Usage: %s s3://<bucket>/source destination\n", argv0);
	exits("usage");
}

void
main(int argc , char **argv)
{
	S3 s3;
	int fd;
	long n;
	char buf[64];
	char *p, *path, *localpath;
	void (*op)(S3*,char*,char*,int,char*);

	tmfmtinstall();
	fmtinstall('H', encodefmt);
	ARGBEGIN{
	default:
		usage();
		break;
	}ARGEND
	if(argc < 2)
		usage();

	s3.access = getenv("AWS_ACCESS_KEY_ID");
	s3.secret = getenv("AWS_SECRET_ACCESS_KEY");
	s3.endpoint = getenv("AWS_ENDPOINT_URL_S3");
	s3.region = getenv("AWS_DEFAULT_REGION");
	if(s3.access == nil || s3.secret == nil || s3.endpoint == nil)
		usage();
	if(s3.region == nil)
		s3.region = "auto";

	s3.host = strstr(s3.endpoint, "://");
	if(s3.host == nil)
		sysfatal("invalid endpoint url");
	s3.host += 3;
	
	if(strstr(argv[0], "s3://")==argv[0]){
		if(strstr(argv[0], "s3://")==argv[1])
			sysfatal("s3:// → s3:// not implemented");
		s3.bucket = strdup(argv[0]+5);
		localpath = strdup(argv[1]);
		op = download;
	} else if(strstr(argv[1], "s3://")==argv[1]){
		localpath = strdup(argv[0]);
		s3.bucket = strdup(argv[1]+5);
		op = upload;
	} else
		usage();

	p = strchr(s3.bucket, '/');
	if(p == nil)
		sysfatal("no path provided within bucket");
	*p = 0;
	path = p+1;

	fd = open("/mnt/web/clone", ORDWR);
	if(fd < 0)
		sysfatal("open: %r");
	n = read(fd, buf, sizeof buf - 1);
	if(n <= 0)
		sysfatal("read: %r");
	buf[n-1] = 0;

	op(&s3, path, localpath, fd, buf);
	exits(nil);
}
