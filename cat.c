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
	Biobuf *b;
	char path[512];

	tmfmtinstall();
	fmtinstall('H', encodefmt);
	i = parseargs(&s3, argc, argv);
	argc -= i;
	argv += i;

	if(argc == 0)
		usage();
	if(parseuri(&s3, path, sizeof path, argv[0]) < 0)
		usage();
	b = Bfdopen(1, OWRITE);
	download(&s3, path, b);
	Bterm(b);
	exits(nil);
}
