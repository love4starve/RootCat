#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../headers/s_crawler.h"
#include "../headers/exploit.h"

static int g_verbose = 0;

int s_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    g_stats.total_scanned++;

    if (g_stats.total_scanned % 15 == 0) {
        char display_path[70];
        size_t len = strlen(fpath);
        if (len > 60) {
            snprintf(display_path, sizeof(display_path), "%.57s...", fpath);
        } else {
            snprintf(display_path, sizeof(display_path), "%s", fpath);
        }

        printf("\r\033[K[\033[0;35mcrawling\033[0m] %s\n\r\033[K[\033[1;36mstats\033[0m] files: \033[1;37m%d\033[0m | suid: \033[1;33m%d\033[0m | vulns: \033[1;31m%d\033[0m\033[1A",
               display_path,
               g_stats.total_scanned,
               g_stats.suid_found,
               g_stats.vulns_found);
        fflush(stdout);
    }

    if (typeflag != FTW_F) {
        return 0;
    }
    if (sb->st_mode & S_ISUID) {
        const char *bin_name = &fpath[ftwbuf->base];
        exploit_binary(bin_name, fpath, g_verbose);
    }
    return 0;
}

void s_crawler(const char *path, int verbose) {
    g_verbose = verbose;
    nftw(path, s_callback, 20, FTW_PHYS);
    printf("\r\033[K\n\r\033[K[\033[0;32mdone\033[0m] %s\n", path);
    fflush(stdout);
}