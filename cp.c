#include <u.h>
#include <libc.h>
#include <bio.h>
#include <mp.h>
#include <libsec.h>
#include "s3.h"
#include "cmd.h"

static void
mimetype(char *path, char *out, int nout)
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
		snprint(out, nout, "%s", buf);
	}
}

static void
upload(S3 *s3, char *localpath, char *remotepath)
{
	DigestState *ds;
	uchar data[8192];
	char mime[32];
	uchar digest[SHA2_256dlen];
	long n;
	int fd;
	char buf[256];
	Hcon con;

	mimetype(localpath, mime, sizeof mime);
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
	sha2_256(nil, 0, digest, ds);
	seek(fd, 0, 0);

	if(s3put(s3, &con, remotepath, mime, digest) < 0)
		sysfatal("upload postbody open: %r");
	for(;;){
		n = read(fd, buf, sizeof buf);
		if(n < 0)
			sysfatal("file read: %r");
		if(n == 0)
			break;
		if(write(con.post, buf, n) < 0)
			sysfatal("upload write: %r");
	}
	if(hdone(&con) < 0)
		sysfatal("error response code: %r");
	hclose(&con);
}

_Noreturn void
usage(void)
{
	fprint(2, "Usage %s: source s3://bucket/dst\n", argv0);
	fprint(2, "Usage %s: s3://bucket/source dst\n", argv0);
	exits("usage");
}

void
main(int argc , char **argv)
{
	S3 s3;
	int i;
	int fd;
	Biobuf *b;
	char path[512];

	tmfmtinstall();
	fmtinstall('H', encodefmt);
	i = parseargs(&s3, argc, argv);
	argc -= i;
	argv += i;

	if(argc < 2)
		usage();
	if(parseuri(&s3, path, sizeof path, argv[0]) == 0){
		if(parseuri(&s3, path, sizeof path, argv[1]) == 0)
			sysfatal("s3:// → s3:// is not implemented");
		fd = create(argv[1], OWRITE, 0644);
		if(fd < 0)
			sysfatal("create: %r");
		b = Bfdopen(fd, OWRITE);
		if(b == nil)
			sysfatal("Bfdopen: %r");
		download(&s3, path, b, s3get);
		Bterm(b);
		exits(nil);
	}
	if(parseuri(&s3, path, sizeof path, argv[1]) < 0)
		usage();
	upload(&s3, argv[0], path);
	exits(nil);
}
