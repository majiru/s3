typedef struct S3 S3;
typedef struct Hcon Hcon;

struct S3 {
	char *endpoint;
	char *host;
	char *access;
	char *bucket;
	char *region;
};

struct Hcon {
	char id[16];
	int ctl, body, post, err;
	int mode;
};

int s3get(S3 *s3, Hcon *con, char *path);
int s3del(S3 *s3, Hcon *con, char *path);
int s3put(S3 *s3, Hcon *con, char *path, char *mime, uchar *payhash);
int s3post(S3 *s3, Hcon *con, char *path);
int s3postwrite(S3 *s3, Hcon *con, char *path, char *mime, uchar *payhash);

void hclose(Hcon *con);
int hdone(Hcon *con);
