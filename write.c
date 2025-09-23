#include <u.h>
#include <libc.h>
#include <bio.h>
#include <mp.h>
#include <libsec.h>
#include "s3.h"
#include "cmd.h"
#include "xml.h"

_Noreturn void
usage(void)
{
	fprint(2, "Usage %s: s3://bucket/dir\n", argv0);
	exits("usage");
}

static char*
putpart(S3 *s3, char *path, int partno, char *uploadid, uchar *data, long n)
{
	Hcon con;
	int fd, ret;
	uchar payhash[SHA2_256dlen];
	char buf[256];
	long etagn;

	sha2_256(data, n, payhash, nil);
	ret = s3put(s3, &con, smprint("%s?partNumber=%d&uploadId=%s", path, partno, uploadid), "application/octet-stream", payhash);
	if(ret < 0)
		sysfatal("part %d upload: s3put: %r", partno);
	if(write(con.post, data, n) != n)
		sysfatal("short write on s3put: %r");
	if(hdone(&con) < 0)
		sysfatal("server responded with error: %r");
	snprint(buf, sizeof buf, "/mnt/web/%s/etag", con.id);
	fd = open(buf, OREAD);
	if(fd < 0)
		sysfatal("no ETAG response header");
	if((etagn = read(fd, buf, sizeof buf - 1)) < 0)
		sysfatal("can't read ETAG response");
	close(fd);
	buf[etagn] = '\0';
	hclose(&con);
	return strdup(buf);
}

static void
finishpart(S3 *s3, char *path, char *tags[], int partmax, char *uploadid)
{
	int ret, i;
	uchar payhash[SHA2_256dlen];
	char buf[8192];
	char *s, *e;
	long errn;
	char errbody[2048];
	Hcon con;

	s = buf;
	e = s + sizeof buf-1;
	s = seprint(s, e, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	s = seprint(s, e, "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n");
	for(i = 1; i < partmax; i++)
		s = seprint(s, e, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>\n", i, tags[i-1]);
	s = seprint(s, e, "</CompleteMultipartUpload>");
	sha2_256((uchar*)buf, s-buf, payhash, nil);
	ret = s3postwrite(s3, &con, smprint("%s?uploadId=%s", path, uploadid), "application/xml", payhash);
	if(ret < 0)
		sysfatal("upload did not complete: %r");
	if(write(con.post, buf, s-buf) != s-buf)
		sysfatal("short write on s3post: %r");
	if(hdone(&con) == 0){
		hclose(&con);
		return;
	}
	errn = read(con.err, errbody, sizeof errbody);
	if(errn <= 0)
		sysfatal("cant read con.err: %r");
	write(2, errbody, errn);
	exits("errorbody");
}

void
main(int argc , char **argv)
{
	S3 s3;
	int i, partno;
	char path[512];
	int p[2];
	Biobuf *b[2];
	Xelem *x;
	static uchar bb[5*1024*1024];
	long n, len;
	static char *tags[256];

	tmfmtinstall();
	fmtinstall('H', encodefmt);
	quotefmtinstall();
	i = parseargs(&s3, argc, argv);
	argc -= i;
	argv += i;

	if(argc == 0)
		usage();
	if(parseuri(&s3, path, sizeof path, argv[0]) < 0)
		usage();
	if(pipe(p) < 0)
		sysfatal("pipe: %r");
	switch(fork()){
	case -1:
		sysfatal("fork: %r");
	case 0:
		close(p[1]);
		b[0] = Bfdopen(p[0], OWRITE);
		if(b[0] == nil)
			sysfatal("Bfdopen: %r");
		download(&s3, smprint("%s?uploads=", path), b[0], s3post);
		Bterm(b[0]);
		exits(nil);
	default:
		waitpid();
		close(p[0]);
		break;
	}
	b[1] = Bfdopen(p[1], OREAD);
	if(b[1] == nil)
		sysfatal("Bfdopen: %r");
	x = xmlread(b[1], 0);
	if(x == nil)
		sysfatal("file was not valid XML, maybe not a prefix?");
	if((x = xmlget(x, "UploadId", nil)) == nil)
		sysfatal("xml did not have UploadId field");

	/* print("%s\n", x->v); */

	for(len = 0, partno = 1;;){
		n = read(0, bb, sizeof bb - len);
		if(n == 0)
			break;
		if(n < 0)	/* Abort probably? */
			sysfatal("read: %r");
		len += n;
		if(len == sizeof bb){
			tags[partno-1] = putpart(&s3, path, partno, x->v, bb, sizeof bb);
			partno++;
			len = 0;
		}
	}
	if(len != 0){
		tags[partno-1] = putpart(&s3, path, partno, x->v, bb, len);
		partno++;
	}

	finishpart(&s3, path, tags, partno, x->v);
	exits(nil);
}
