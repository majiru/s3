#include <u.h>
#include <libc.h>
#include <bio.h>
#include "s3.h"

static void
dump(Hcon *con, Biobuf *out)
{
	long n;
	char data[8192];

	for(;;){
		n = read(con->body, data, sizeof data);
		if(n < 0)
			sysfatal("download body: %r");
		if(n == 0){
			hclose(con);
			return;
		}
		Bwrite(out, data, n);
	}
}

void
download(S3 *s3, char *path, Biobuf *local, int (*fn)(S3*,Hcon*,char*))
{
	Hcon con;

	if(fn(s3, &con, path) < 0)
		sysfatal("failed to create request: %r");
	dump(&con, local);
}

void
downloadrange(S3 *s3, char *path, Biobuf *local, long off, long n)
{
	Hcon con;

	if(s3getrange(s3, &con, path, off, n) < 0)
		sysfatal("failed to create request: %r");
	dump(&con, local);
}

int
parseuri(S3 *s3, char *path, int npath, char *arg)
{
	char *p;

	if(strstr(arg, "s3://") != arg)
		return -1;
	arg+=5;
	p = strchr(arg, '/');
	if(p == nil || p == arg)
		return -1;
	snprint(path, npath, "%s", p+1);
	s3->bucket = strdup(arg);
	s3->bucket[p-arg] = 0;
	return 0;
}

int
parseargs(S3 *s3, int argc, char **argv)
{
	extern _Noreturn void usage(void);
	int initial;

	initial = argc;
	s3->access = s3->endpoint = s3->region = nil;
	ARGBEGIN{
	case 'a':
		s3->access = strdup(EARGF(usage()));
		break;
	case 'u':
		s3->endpoint = strdup(EARGF(usage()));
		break;
	case 'r':
		s3->region = strdup(EARGF(usage()));
		break;
	}ARGEND

	if(s3->access == nil)
		s3->access = getenv("AWS_ACCESS_KEY_ID");
	if(s3->endpoint == nil)
		s3->endpoint = getenv("AWS_ENDPOINT_URL_S3");
	if(s3->region)
		s3->region = getenv("AWS_DEFAULT_REGION");

	if(s3->access == nil || s3->endpoint == nil)
		usage();
	if(s3->region == nil)
		s3->region = strdup("auto");

	s3->host = strstr(s3->endpoint, "://");
	if(s3->host == nil)
		sysfatal("invalid endpoint url");
	s3->host += 3;
	return initial-argc;
}
