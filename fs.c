#include <u.h>
#include <libc.h>
#include <auth.h>
#include <thread.h>
#include <fcall.h>
#include <9p.h>
#include <mp.h>
#include <libsec.h>
#include <bio.h>
#include "s3.h"
#include "xml.h"
#include "cmd.h"

typedef struct Xfid Xfid;
typedef struct Tab Tab;
typedef struct Child Child;

struct Child {
	char name[128];
	uchar type;
};

struct Xfid {
	char path[512];
	int nc;
	Child *c;
};

struct Tab {
	char key[512];
	uvlong val;
	Tab *next;
};

Tab table[256];
uvlong nextqid;
S3 s3;

static ulong
shash(char *s)
{
	ulong hash;

	hash = 7;
	for(; *s; s++)
		hash = hash*31  + *s;
	return hash;
}

static uvlong
findoradd(char *s)
{
	Tab *e, **ep;

	e = &table[shash(s)%nelem(table)];
	ep = &e;
	if(e->key == nil)
		goto Add;
	for(; e != nil; e = e->next){
		ep = &e->next;
		if(strcmp(e->key, s) == 0)
			return e->val;
	}
	*ep = mallocz(sizeof *e, 1);
Add:
	snprint((*ep)->key, sizeof (*ep)->key, "%s", s);
	(*ep)->val = nextqid++;
	return (*ep)->val;
}

static void
fsattach(Req *r)
{
	Xfid *x;

	r->fid->aux = mallocz(sizeof(Xfid), 1);
	x = r->fid->aux;
	x->path[0] = '/', x->path[1] = '\0';
	r->fid->qid = (Qid){findoradd(x->path), 0, QTDIR};
	r->ofcall.qid = r->fid->qid;
	respond(r, nil);
}

static int
yoinkfiles(Xelem *x, char *dst[], int ndst, int trim)
{
	int n;
	Xelem *key;
	Xelem *i;

	/* Sanity check */
	for(i = x; i != nil; i = i->next){
		if(strcmp(i->n, "ListBucketResult") == 0)
			goto Valid;
	}
	werrstr("xml result did not include ListBucketResult");
	return -1;

Valid:
	x = xmlget(x, "Contents", nil);
	if(x == nil)
		return 0;

	for(n = 0; x != nil && ndst > 0; x = x->next, ndst--){
		key = xmlget(x, "Key", nil);
		if(key == nil) 
			continue;
		dst[n++] = strdup(key->v + trim);
	}
	return n;
}

static int
s3ls(char *url, char *dst[], int ndst, int trim)
{
	char buf[2048];
	Hcon con;
	int n;
	long count;
	Xelem *raw;
	Bstr *b;

	if(s3get(&s3, &con, url) < 0){
		werrstr("file does not exist: %r");
		return -1;
	}
	count = read(con.body, buf, sizeof buf);
	if(count <= 0){
		werrstr("read error on list body");
		return -1;
	}
	b = Bstropen(buf, count);
	raw = xmlread(b, 0);
	if(raw == nil){
		werrstr("s3 did not give us valid xml");
		return -1;
	}
	Bterm(b);
	n = yoinkfiles(raw, dst, ndst, trim);
	xmlfree(raw);

	return n;
}

static void
packwalk(Req *r, uchar qtype, char *prefix, char *path)
{
	char key[512];
	char *p;
	int i;
	int skip;

	for(skip = 0, p = prefix+1; p = strchr(p, '/'); p++)
		skip++;
	for(i = 0, p = path; p = strchr(p, '/'); p++){
		if(skip--)
			continue;
		snprint(key, sizeof key, "%s%.*s", prefix, (int)(p-path)+1, path);
		r->ofcall.wqid[i++] = (Qid){findoradd(key), 0, QTDIR};
	}
	if(qtype == QTDIR)
		snprint(key, sizeof key, "%s%s/", prefix, path);
	else
		snprint(key, sizeof key, "%s%s", prefix, path);
	r->ofcall.wqid[i++] = (Qid){findoradd(key), 0, qtype};
	r->ofcall.nwqid = i;
}

static void
fswalk(Req *r)
{
	char path[512], url[512];
	char *files[128];
	char *p, *e;
	int i, n, len;
	Xfid *x, *dst;

	e = path + sizeof path;
	p = path;
	x = r->fid->aux;

	if(r->ifcall.newfid != r->ifcall.fid){
		r->newfid->aux = mallocz(sizeof(Xfid), 1);
		dst = r->newfid->aux;
		memcpy(dst->path, x->path, sizeof x->path);
	} else
		dst = x;
	if(r->ifcall.nwname == 0)
		goto Done;
	//Our paths start at /, s3's do not
	snprint(path, sizeof path, "%s", dst->path+1);
	for(i = 0; i < r->ifcall.nwname-1; i++)
		p = seprint(p, e, "%s%s", r->ifcall.wname[i], "/");
	snprint(url, sizeof url, "?list-type=2&prefix=%U", path);
	n = s3ls(url, files, nelem(files), strlen(path));
	if(n < 0){
		responderror(r);
		return;
	}
	if(n == 0){
		respond(r, "no Key's in result");
		return;
	}

	/*
	 * s3 doesn't really have dirs and files,
	 * it just has files which can have / in the name.
	 * Common uses still use / as a path seperator, so we can do that.
	 * However, all we get back from a list are keys, so we need to fabricate
	 * directories on the fly.
	 */
	p = r->ifcall.wname[r->ifcall.nwname-1];
	len = strlen(p);
	for(i = 0; i < n; i++){
		if(strcmp(files[i], p) == 0){
			//Exact match, a file.
			packwalk(r, QTFILE, x->path, path);
			snprint(dst->path, sizeof dst->path, "/%s%s", path, files[i]);
			goto Done;
		}
		if(strncmp(files[i], p, len) == 0 && files[i][len] == '/'){
			//There are keys under, we're a directory
			packwalk(r, QTDIR, x->path, path);
			snprint(dst->path, sizeof dst->path, "/%s%.*s/", path, len, files[i]);
			goto Done;
		}
	}
	// No results
	respond(r, "file does not exist");
	return;

Done:
	respond(r, nil);
}

static void
fsopen(Req *r)
{
	respond(r, nil);
}

static void
fsclose(Req *r)
{
	Xfid *x;

	x = r->fid->aux;
	if(x->c){
		//Only cache list results until file is closed
		free(x->c);
		x->c = nil;
	}
	respond(r, nil);
}

static void
filldir(Dir *d, uchar type, char *path)
{
	char *p;

	d->qid = (Qid){findoradd(path), 0, type};
	d->mode = 0555;
	d->atime = 0;
	d->mtime = 0;
	d->length = 0;
	if(path[0] == '/' && path[1] == '\0')
		d->name = estrdup9p("/");
	else {
		p = strrchr(path, '/');
		if(type == QTDIR){
			d->mode |= DMDIR;
			p--;
			while(*p != '/')
				p--;
			d->name = estrdup9p(p+1);
			p = strchr(d->name, '/');
			*p = '\0';
			
		} else
			d->name = estrdup9p(p+1);
	}
	d->uid = estrdup9p("sys");
	d->gid = estrdup9p("sys");
	d->muid = estrdup9p("sys");
}

static int
dirgen(int n, Dir *d, void *aux)
{
	Xfid *x;

	x = aux;
	if(n >= x->nc)
		return -1;
	filldir(d, x->c[n].type, x->c[n].name);
	return 0;
}

static void
fsread(Req *r)
{
	Hcon con;
	int i, ret;
	long n, wr;
	char *files[128];
	char url[512];
	Xfid *x;
	char *p;
	uchar type;
	char err[ERRMAX];

	x = r->fid->aux;
	switch(r->fid->qid.type){
	case QTFILE:
		wr = 0;
		ret = s3getrange(&s3, &con, x->path+1, r->ifcall.offset, r->ifcall.count);
		if(ret < 0){
			rerrstr(err, ERRMAX);
			if(strstr(err, "416 Range Not Satisfiable") == err)
				goto Doneread;
			responderror(r);
			return;
		}
		for(;;){
			n = read(con.body, r->ofcall.data+wr, r->ifcall.count-wr);
			if(n == 0)
				break;
			if(n < 0){
				respond(r, "read error: %r");
				return;
			}
			wr += n;
		}
Doneread:
		r->ofcall.count = wr;
		respond(r, nil);
		return;
	case QTDIR:
		if(x->c == nil){
			snprint(url, sizeof url, "?list-type=2&prefix=%U", x->path+1);
			n = s3ls(url, files, nelem(files), strlen(x->path+1));
			if(n < 0){
				responderror(r);
				return;
			}
			x->c = mallocz(sizeof *x->c * n, 1);
			x->nc = 0;
			for(i = 0; i < n; i++){
				p = strchr(files[i], '/');
				if(p){
					type = QTDIR;
					*p = '\0';
				} else
					type = QTFILE;
				snprint(x->c[x->nc].name, 128, "%s%s%s", x->path, files[i], type == QTDIR ? "/" : "");
				x->c[x->nc++].type = type;
			}
		}
		dirread9p(r, dirgen, x);
		respond(r, nil);
		return;
	}
}

static void
fsstat(Req *r)
{
	Xfid *x;

	x = r->fid->aux;
	filldir(&r->d, r->fid->qid.type, x->path);
	respond(r, nil);
}

static void
fsdestroy(Fid *fid)
{
	Xfid *x;

	if(fid->aux){
		x = fid->aux;
		free(x->c);
	}
}

Srv fs = {
	.attach=fsattach,
	.walk=fswalk,
	.read=fsread,
	.stat=fsstat,
	.destroyfid=fsdestroy,
};

_Noreturn void
usage(void)
{
	fprint(2, "Usage: %s [-Dabr] [-m mntpt] [-s srv] bucket\n", argv0);
	exits("usage");
}

void
main(int argc, char **argv)
{
	int mflag;
	char *mntpt, *srvname;

	s3fmtinstall();
	tmfmtinstall();
	fmtinstall('H', encodefmt);
	parseargs(&s3, argc, argv);

	mflag = MREPL;
	mntpt = srvname = nil;
	ARGBEGIN{
	case 'D':
		chatty9p++;
		break;
	case 'a':
		mflag = MAFTER;
		break;
	case 'b':
		mflag = MBEFORE;
		break;
	case 'm':
		mntpt = EARGF(usage());
		break;
	case 'r':
		mflag = MREPL;
		break;
	case 's':
		srvname = EARGF(usage());
		break;
	}ARGEND
	if(argc == 0)
		usage();

	s3.bucket = argv[0];
	if(mntpt == nil && srvname == nil)
		mntpt = smprint("/n/%s", argv[0]);
	postmountsrv(&fs, srvname, mntpt, mflag);
	exits(nil);
}
