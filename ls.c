#include <u.h>
#include <libc.h>
#include <bio.h>
#include "s3.h"
#include "cmd.h"
#include "xml.h"

_Noreturn void
usage(void)
{
	fprint(2, "Usage %s: s3://bucket/dir\n", argv0);
	exits("usage");
}

void
main(int argc , char **argv)
{
	S3 s3;
	int i;
	char path[512];
	char *pp;
	int p[2];
	Biobuf *b[2];
	Xelem *x;

	tmfmtinstall();
	fmtinstall('H', encodefmt);
	s3fmtinstall();
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
		if(path[0] == '\0')
			pp = path;
		else
			pp = smprint("?list-type=2&prefix=%U", path);
		fprint(2, "%s\n", pp);
		download(&s3, pp, b[0], s3get);
		Bterm(b[0]);
		exits(nil);
	default:
		close(p[0]);
		break;
	}
	b[1] = Bfdopen(p[1], OREAD);
	if(b[1] == nil)
		sysfatal("Bfdopen: %r");
	x = xmlread(b[1], 0);
	if(x == nil)
		sysfatal("response was not valid XML, maybe not a prefix?");
	if((x = xmlget(x, "Contents", nil)) == nil)
		sysfatal("xml did not have Contents field");

	for(; x != nil && xmlget(x, "Key", nil) != nil; x = x->next)
		print("%s\n", xmlget(x, "Key", nil)->v);
	exits(nil);
}
