#include <u.h>
#include <libc.h>
#include <bio.h>
#include "s3.h"
#include "cmd.h"

_Noreturn void
usage(void)
{
	fprint(2, "Usage %s: s3://bucket/file\n", argv0);
	exits("usage");
}

void
main(int argc , char **argv)
{
	S3 s3;
	int i;
	char path[512];
	Hcon con;

	tmfmtinstall();
	fmtinstall('H', encodefmt);
	i = parseargs(&s3, argc, argv);
	argc -= i;
	argv += i;

	if(argc == 0)
		usage();
	if(parseuri(&s3, path, sizeof path, argv[0]) < 0)
		usage();
	if(s3del(&s3, &con, path) < 0)
		sysfatal("could not build request: %r");
	exits(nil);
}
