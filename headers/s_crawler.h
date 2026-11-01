#define _XOPEN_SOURCE 500
#ifndef S_CRAWLER_H
#define S_CRAWLER_H

#include <sys/stat.h>
#include <ftw.h>

void s_crawler(const char *path, int verbose);
int s_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);

#endif