#include <u.h>
#include <libc.h>
#include <auth.h>
#include <thread.h>
#include <fcall.h>
#include <9p.h>
#include <mp.h>
#include <libsec.h>

static char *user;
static Attr *creds;

enum {
	Sneedparam,
	Shaveparam,
};

typedef struct State State;
struct State {
	uchar buf[SHA2_256dlen];
	uint phase;
};

static uint
aws4write(State *s, char *v, uint l)
{
	char input[512];
	char *args[3];
	int n;
	char buf[256];

	switch(s->phase){
	case Shaveparam:
		werrstr("%s", "read the results");
		return ARphase;
	case Sneedparam:
		/* date region service */
		snprint(input, sizeof input, "%.*s", (int)l, v);
		n = tokenize(input, args, nelem(args));
		if(n != nelem(args)){
			werrstr("%s", "invalid rpc format");
			return ARerror;
		}
		/* All lights are green */
		snprint(buf, sizeof buf, "AWS4%s", _strfindattr(creds, "!secret"));
		hmac_sha2_256((uchar*)args[0], strlen(args[0]), (uchar*)buf, strlen(buf), s->buf, nil);
		hmac_sha2_256((uchar*)args[1], strlen(args[1]), s->buf, SHA2_256dlen, (uchar*)buf, nil);
		hmac_sha2_256((uchar*)args[2], strlen(args[2]), (uchar*)buf, SHA2_256dlen, s->buf, nil);
		hmac_sha2_256((uchar*)"aws4_request", 12, s->buf, SHA2_256dlen, s->buf, nil);
		memset(input, 0, sizeof input);
		memset(buf, 0, sizeof buf);
		s->phase = Shaveparam;
		return ARok;
	}
	return ARrpcfailure;
}

static uint
aws4read(State *s, char *v, uint *l)
{
	switch(s->phase){
	case Sneedparam:
		werrstr("%s", "write the params");
		return ARphase;
	case Shaveparam:
		assert(*l > SHA2_256dlen);
		*l = SHA2_256dlen;
		memmove(v, s->buf, SHA2_256dlen);
		memset(s->buf, 0, SHA2_256dlen);
		s->phase = Sneedparam;
		return ARok;
	}
	return ARrpcfailure;
}

enum {
	Qroot,
	Qrpc,
	Qctl,
	Nqid,

	Qfile = Qrpc,
};

static int
attrfmt(Fmt *fmt)
{
	Attr *a;
	int first = 1;

	for(a=va_arg(fmt->args, Attr*); a != nil; a=a->next){
		if(a->name == nil)
			continue;
		switch(a->type){
		default:
			continue;
		case AttrQuery:
			fmtprint(fmt, first+" %q?", a->name);
			break;
		case AttrNameval:
		case AttrDefault:
			if(a->name[0] == '!')
				fmtprint(fmt, first+" %q", a->name);
			else
				fmtprint(fmt, first+" %q=%q", a->name, a->val);
			break;
		}
		first = 0;
	}
	return 0;
}

struct {
	char *name;
	int mode;
	int type;
} qtab[Nqid] = {
	"/",
		DMDIR|0500,
		QTDIR,
	"rpc",
		0600,
		0,
	"ctl",
		0600,
		0,
};

static int
dirgen(int n, Dir *dir, void*)
{
	n += Qfile; /* offset to make dirread9p happy */

	if(n >= Nqid)
		return -1;
	dir->name = estrdup9p(qtab[n].name);
	dir->uid = estrdup9p(user);
	dir->gid = estrdup9p(user);
	dir->muid = estrdup9p("");
	dir->qid = (Qid){n, 0, qtab[n].type};
	dir->mode = qtab[n].mode;
	return 0;
}

static void
fsstat(Req *r)
{
	int path;

	path = r->fid->qid.path;
	assert(r->fid->qid.path < Nqid);
	dirgen(path-Qfile, &r->d, nil);
	respond(r, nil);
}

char Enonexist[] = "file does not exist";
char Ewalk[] = "walk in non directory";

static char*
fswalk1(Fid *fid, char *name, Qid *qid)
{
	int i;
	ulong path;

	path = fid->qid.path;
	switch(path){
	case Qroot:
		if(strcmp(name, "..") == 0)
			name = "/";
		for(i = path; i<Nqid; i++){
			if(strcmp(name, qtab[i].name) != 0)
				continue;
			*qid = (Qid){i, 0, qtab[i].type};
			fid->qid = *qid;
			return nil;
		}
		return Enonexist;
	default:
		return Ewalk;
	}
}

enum {
	FSwrite,
	FSread,	
};

typedef struct Xfid Xfid;
struct Xfid {
	State proto;
	uint expect;
	uint nmsg;
	char msg[512];
};

static void
fsopen(Req *r)
{
	if(r->fid->qid.path == Qrpc)
		r->fid->aux = mallocz(sizeof(Xfid), 1);
	respond(r, nil);
}

static void
fsclose(Fid *f)
{
	if(f->qid.path == Qrpc)
		free(f->aux);
}

static void
fsread(Req *r)
{
	ulong path;
	char buf[512];
	Xfid *x;

	path = r->fid->qid.path;
	switch(path){
	case Qroot:
		dirread9p(r, dirgen, nil);
		respond(r, nil);
		break;
	case Qctl:
		snprint(buf, sizeof buf, "%A\n", creds);
		readstr(r, buf);
		respond(r, nil);
		break;
	case Qrpc:
		x = r->fid->aux;
		if(x->expect != FSread){
			respond(r, "error read without a rpc verb write first");
			break;
		}
		r->ifcall.offset = 0;
		readbuf(r, x->msg, x->nmsg);
		respond(r, nil);
		x->expect = FSwrite;
		break;
	default:
		respond(r, "not implemented");
		break;
	}
}

static void
fswrite(Req *r)
{
	ulong path;
	char buf[512];
	char *proto;
	Xfid *x;
	uint res;
	char outbuf[512];
	uint noutbuf;

	path = r->fid->qid.path;
	r->ofcall.count = snprint(buf, sizeof buf, "%.*s", r->ifcall.count, r->ifcall.data);
	switch(path){
	case Qctl:
		if(strncmp(buf, "key ", 4) == 0){
			_freeattr(creds);
			creds = _parseattr(buf+4);
			if((proto = _strfindattr(creds, "proto")) == nil || strcmp(proto, "aws4") != 0)
				respond(r, "proto!=aws4");
			else
				respond(r, nil);
		} else if(strncmp(buf, "delkey", 6) == 0){
			_freeattr(creds);
			creds = nil;
			respond(r, nil);
		} else
			respond(r, "unknown ctl msg");
		memset(buf, 0, sizeof buf);
		break;
	case Qrpc:
		x = r->fid->aux;
		if(x->expect != FSwrite){
			respond(r, "error write while there's data for you to read");
			return;
		}
		if(strncmp(buf, "start", 5) == 0)
			res = ARok;
		else if(strncmp(buf, "write ", 6) == 0)
			res = aws4write(&x->proto, buf+6, r->ifcall.count-6);
		else if(strncmp(buf, "read", 4) == 0){
			noutbuf = sizeof outbuf;
			res = aws4read(&x->proto, outbuf, &noutbuf);
			if(res == ARok){
				x->nmsg = 2+1+SHA2_256dlen;
				memcpy(x->msg, "ok ", 3);
				memcpy(x->msg+3, outbuf, SHA2_256dlen);
				respond(r, nil);
				x->expect = FSread;
				return;
			}
		} else {
			respond(r, "invalid rpc verb");
			return;
		}
		switch(res){
		case ARok:
			x->nmsg = snprint(x->msg, sizeof x->msg, "ok");
			break;
		case ARphase:
			x->nmsg = snprint(x->msg, sizeof x->msg, "phase %r");
			break;
		default:
			x->nmsg = snprint(x->msg, sizeof x->msg, "error %r");
			break;
		}
		x->expect = FSread;
		respond(r, nil);
		break;
	default:
		respond(r, "not implemented");
	}
}

static void
fsattach(Req *r)
{
	r->fid->qid = (Qid){Qroot, 0, QTDIR};
	r->ofcall.qid = r->fid->qid;
	respond(r, nil);
}

Srv fs = {
.read=fsread,
.write=fswrite,
.attach=fsattach,
.stat=fsstat,
.walk1=fswalk1,
.open=fsopen,
.destroyfid=fsclose,
};

_Noreturn static void
usage(void)
{
	fprint(2, "Usage: %s [-D] [-s srv] [-m mntpt]\n", argv0);
	exits("usage");
}

void
main(int argc, char **argv)
{
	char *srv, *mntpt;

	srv = nil;
	mntpt = "/mnt/factotum";
	ARGBEGIN{
	case 'D':
		chatty9p++;
		break;
	case 's':
		srv = EARGF(usage());
		break;
	case 'm':
		mntpt = EARGF(usage());
		break;
	default:
		usage();
	}ARGEND

	user = getenv("user");
	if(user == nil)
		sysfatal("no $user");
	quotefmtinstall();
	fmtinstall('A', attrfmt);
	postmountsrv(&fs, srv, mntpt, MBEFORE);
	exits(nil);
}
