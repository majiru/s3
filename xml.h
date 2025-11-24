typedef struct Xelem Xelem;
typedef struct Xattr Xattr;

struct Xelem
{
	char  *n;
	char  *v;
	Xattr *a;
	Xelem *ch;
	Xelem *next;
	void  *priv;
};

struct Xattr
{
	char  *n;
	char  *v;
	Xattr *next;
};

enum
{
	Xmlstartonly = 1,
};

Xelem *xmlread(Biobufhdr *b, int flags);
void xmlfree(Xelem *x);
Xelem *xmlget(Xelem *x, char *path, ...);
Xattr *xmlgetattr(Xattr *a, char *n);
void xmlprint(Xelem *x, int fd);
