#include <u.h>
#include <libc.h>
#include <auth.h>
#include <mp.h>
#include <libsec.h>

#define hmac(data, dlen, key, klen, digest) hmac_sha2_256(data, dlen, key, klen, digest, nil)

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

void
main(int,char**)
{
	char *o;
	char *s;
	int pid;
	int fd;
	AuthRpc *rpc;
	int ret;
	uchar buf[SHA2_256dlen];

	rfork(RFNAMEG);
	o = getenv("O");
	if(o == nil)
		sysfatal("no $O");
	switch(pid = fork()){
	case -1:
		sysfatal("fork");
	case 0:
		execl(smprint("../%s.factotum", o), "factotum", nil);
		sysfatal("exec");
	default:
		while(waitpid() != pid)
			;
		break;
	}

	fmtinstall('H', encodefmt);
	fd = open("/mnt/factotum/ctl", OWRITE);
	if(fd < 0)
		sysfatal("open: %r");
	if(fprint(fd, "key proto=aws4 !secret=blah access=myid") < 0)
		sysfatal("key write: %r");
	close(fd);

	fd = open("/mnt/factotum/rpc", ORDWR);
	if(fd < 0)
		sysfatal("open: %r");

	rpc = auth_allocrpc(fd);
	ret = auth_rpc(rpc, "start", "proto=aws4 access=myid", strlen("proto=aws4 access=myid"));
	if(ret != ARok)
		sysfatal("start: %r");

	s = smprint("somedate auto s3");
	ret = auth_rpc(rpc, "write", s, strlen(s));
	if(ret != ARok)
		sysfatal("write: %r");

	ret = auth_rpc(rpc, "read", nil, 0);
	if(ret != ARok)
		sysfatal("read: %r");
	mkkey("blah", "somedate", "auto", "s3", buf);

	if(memcmp(rpc->arg, buf, SHA2_256dlen) != 0)
		sysfatal("mismatch %.*lH %.*lH", SHA2_256dlen, rpc->arg, SHA2_256dlen, buf);

	auth_freerpc(rpc);
	exits(nil);
}
