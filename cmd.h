void download(S3*, char*, Biobuf*, int (*fn)(S3*,Hcon*,char*));
void downloadrange(S3*, char*, Biobuf*, long, long);
int parseuri(S3*, char*, int, char*);
int parseargs(S3*, int, char**);
void dumperr(Hcon*);
