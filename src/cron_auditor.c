#include "../headers/cron_auditor.h"
#include "../headers/exploit.h"
#include "../headers/spinner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void check_cron_file(const char *filepath) {
    if (access(filepath, R_OK) != 0) return;

    FILE *fp = fopen(filepath, "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || strlen(line) < 5) continue;

        if (strstr(line, "tar ") && strstr(line, "*")) {
            stop_spinner();
            printf("[\033[1;33m!\033[0m] Cron wildcard exploit in %s: %s", filepath, line);
            start_spinner("auditing scheduled cron jobs...");
        }
    }
    fclose(fp);
}

void audit_cron_jobs(int verbose) {
    (void)verbose;
    start_spinner("auditing scheduled cron jobs...");
    check_cron_file("/etc/crontab");
    check_cron_file("/etc/cron.d/root");
    stop_spinner();
}
