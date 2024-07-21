#ifndef MINIGZIP_H
#define MINIGZIP_H
#include <zlib.h>

void error(const char *msg);
void gz_compress(FILE *in, gzFile out);
#ifdef USE_MMAP
int gz_compress_mmap(FILE *in, gzFile out);
#endif
void gz_uncompress(gzFile in, FILE *out);
void file_compress(const char *file, const char *mode);
void file_uncompress(const char *file);
char *file_uncompress_origname(const char *infile, const char *path);

#endif /* MINIGZIP_H */
