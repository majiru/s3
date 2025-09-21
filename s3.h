typedef struct {
	char *endpoint;
	char *host;
	char *access;
	char *bucket;
	char *region;
} S3;

int s3get(S3 *s3, char *path);
int s3del(S3 *s3, char *path);
int s3put(S3 *s3, char *path, char *mime, uchar *payhash);
