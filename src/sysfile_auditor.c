#include "../headers/sysfile_auditor.h"
#include "../headers/exploit.h"
#include "../headers/spinner.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void audit_system_files(int verbose) {
    (void)verbose;
    start_spinner("auditing system file permissions...");

    if (access("/etc/passwd", W_OK) == 0) {
        stop_spinner();
        printf("[\033[1;31m+\033[0m] /etc/passwd is WRITABLE by current user!\n");
        start_spinner("auditing system file permissions...");
    }

    if (access("/etc/shadow", W_OK) == 0) {
        stop_spinner();
        printf("[\033[1;31m+\033[0m] /etc/shadow is WRITABLE by current user!\n");
        start_spinner("auditing system file permissions...");
    }

    if (access("/etc/shadow", R_OK) == 0) {
        stop_spinner();
        printf("[\033[1;33m+\033[0m] /etc/shadow is READABLE by current user!\n");
        start_spinner("auditing system file permissions...");
    }

    stop_spinner();
}
