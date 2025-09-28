#include <u.h>
#include <libc.h>
#include <bio.h>
#include "s3.h"
#include "cmd.h"

_Noreturn void
usage(void)
{
	fprint(2, "Usage %s: [-o offset] [-n count] s3://bucket/file\n", argv0);
	exits("usage");
}

void
main(int argc , char **argv)
{
	S3 s3;
	Biobuf *b;
	char path[512];
	long offset, n;
	int dorange;

	tmfmtinstall();
	fmtinstall('H', encodefmt);
	parseargs(&s3, argc, argv);
	dorange = 0;
	offset = n = -1;
	ARGBEGIN{
	case 'o':
		dorange++;
		offset = atoi(EARGF(usage()));
		break;
	case 'n':
		dorange++;
		n = atoi(EARGF(usage()));
		break;
	}ARGEND

	if(argc == 0)
		usage();
	if(dorange && (offset == -1 || n == -1)){
		fprint(2, "if using ranges both -o and -n must be specified\n");
		exits("usage");
	}
	if(parseuri(&s3, path, sizeof path, argv[0]) < 0)
		usage();
	b = Bfdopen(1, OWRITE);
	if(dorange)
		downloadrange(&s3, path, b, offset, n);
	else
		download(&s3, path, b, s3get);
	Bterm(b);
	exits(nil);
}
