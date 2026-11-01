#define _XOPEN_SOURCE 500
#include "headers/exploit.h"
#include "headers/s_crawler.h"
#include "headers/sudo_auditor.h"
#include "headers/cap_auditor.h"
#include "headers/cron_auditor.h"
#include "headers/sysfile_auditor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_last_vuln_count = 0;
static int g_menu_opened = 0;

void print_banner(int fast_mode, int verbose_mode) {
    printf(
        "\n     /\\___/\\    "
        "\n     )     (      "
        "\n    =\\     /= "
        "\n      )   (      rootcat"                       
        "\n     /     \\     "
        "\n     )     (     fast: %s"
        "\n    /       \\    verbose: %s"            
        "\n    \\       / "
        "\n     \\__ __/  " 
        "\n        ))    "
        "\n       //     " 
        "\n      ((      "
        "\n       \\)     \n\n",
        fast_mode ? "\033[1;32mon\033[0m" : "\033[1;31moff\033[0m",
        verbose_mode ? "\033[1;32mon\033[0m" : "\033[1;31moff\033[0m"
    );
}

void print_help(const char *prog) {
    printf("usage: %s [-h] [-f] [-v] [-p PATH] [PATH]\n", prog);
    printf("flags:\n");
    printf("  -h, --help      help menu\n");
    printf("  -f, --fastmode  fast scan (standard bin paths)\n");
    printf("  -v, --verbose   verbose output\n");
    printf("  -p, --path      scan path target\n");
}

void get_timestamp(char *buffer, size_t size) {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(buffer, size, "%H:%M:%S (%Z)", info);
}

static int check_phase_vulns_and_prompt(const char *phase_name) {
    if (g_vuln_count > g_last_vuln_count) {
        int new_vulns = g_vuln_count - g_last_vuln_count;
        g_last_vuln_count = g_vuln_count;

        printf("\033[?25h");
        printf("[\033[1;31m!\033[0m] %d new target(s) found in %s! [m]enu / [c]ontinue scan: ", new_vulns, phase_name);
        char ans[10];
        if (scanf("%9s", ans) == 1 && (ans[0] == 'm' || ans[0] == 'M')) {
            g_menu_opened = 1;
            int ret = prompt_vuln_selection();
            if (ret == -1) {
                return 0;
            }
        }
        printf("\033[?25l");
    } else {
        printf("[\033[0;32m*\033[0m] %s finished: no new targets found\n", phase_name);
    }
    return 1;
}

int main(int argc, char *argv[]) {
    int fast_mode = 0;
    int verbose_mode = 0;
    const char *scan_path = "/";
    time_t start_time = time(NULL);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fastmode") == 0) {
            fast_mode = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose_mode = 1;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--path") == 0) {
            if (i + 1 < argc) {
                scan_path = argv[++i];
            }
        } else {
            scan_path = argv[i];
        }
    }

    print_banner(fast_mode, verbose_mode);
    printf("\033[?25l");

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    printf("[\033[0;36m*\033[0m] Starting scan at %s\n", timestamp);

    printf("[\033[0;36m*\033[0m] Phase 1: SUID crawler\n");
    if (fast_mode) {
        s_crawler("/usr/bin", verbose_mode);
        s_crawler("/bin", verbose_mode);
        s_crawler("/usr/local/bin", verbose_mode);
        s_crawler("/usr/sbin", verbose_mode);
        s_crawler("/sbin", verbose_mode);
    } else {
        s_crawler(scan_path, verbose_mode);
    }
    if (!check_phase_vulns_and_prompt("SUID crawler")) goto finish;

    printf("[\033[0;36m*\033[0m] Phase 2: Sudoers rules\n");
    audit_sudo_rules(verbose_mode);
    if (!check_phase_vulns_and_prompt("Sudoers rules")) goto finish;

    printf("[\033[0;36m*\033[0m] Phase 3: Capabilities\n");
    audit_capabilities(verbose_mode);
    if (!check_phase_vulns_and_prompt("Capabilities")) goto finish;

    printf("[\033[0;36m*\033[0m] Phase 4: Cron jobs\n");
    audit_cron_jobs(verbose_mode);
    if (!check_phase_vulns_and_prompt("Cron jobs")) goto finish;

    printf("[\033[0;36m*\033[0m] Phase 5: System file permissions\n");
    audit_system_files(verbose_mode);
    if (!check_phase_vulns_and_prompt("System files")) goto finish;

finish:
    printf("\033[?25h");

    time_t end_time = time(NULL);
    double elapsed = difftime(end_time, start_time);
    get_timestamp(timestamp, sizeof(timestamp));

    printf("[\033[0;36m*\033[0m] Scan completed at %s (took %.0fs)\n", timestamp, elapsed);

    if (!g_menu_opened || g_vuln_count > g_last_vuln_count) {
        prompt_vuln_selection();
    }

    return 0;
}
