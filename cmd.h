void download(S3*, char*, Biobuf*, int (*fn)(S3*,Hcon*,char*));
int parseuri(S3*, char*, int, char*);
int parseargs(S3*, int, char**);
