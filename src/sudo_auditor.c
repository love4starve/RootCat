#include "../headers/sudo_auditor.h"
#include "../headers/exploit.h"
#include "../headers/spinner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

static char *trim_whitespace(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static void safe_copy_str(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

void audit_sudo_rules(int verbose) {
    (void)verbose;

    start_spinner("checking sudoers permissions...");

    FILE *fp = popen("sudo -n -l 2>/dev/null", "r");
    if (!fp) {
        stop_spinner();
        return;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp)) {
        char *nopasswd_ptr = strstr(buffer, "NOPASSWD:");
        if (!nopasswd_ptr) {
            continue;
        }

        stop_spinner();
        printf("[\033[1;32m+\033[0m] Sudoers NOPASSWD rule found!\n");
        nopasswd_ptr += strlen("NOPASSWD:");

        char *saveptr;
        char *token = strtok_r(nopasswd_ptr, ",", &saveptr);
        while (token != NULL) {
            char *clean_token = trim_whitespace(token);
            if (strlen(clean_token) > 0) {
                char binary_path[512];
                safe_copy_str(binary_path, clean_token, sizeof(binary_path));

                char *space_ptr = strchr(binary_path, ' ');
                if (space_ptr) {
                    *space_ptr = '\0';
                }

                char *bin_name = strrchr(binary_path, '/');
                if (bin_name) {
                    bin_name++;
                } else {
                    bin_name = binary_path;
                }

                const GTFOBinPayload *payload = find_gtfobin_payload(bin_name);
                if (payload) {
                    printf("   ↳ Vulnerable: %s (%s)\n", binary_path, payload->description);
                    if (g_vuln_count < MAX_DISCOVERED_VULNS) {
                        safe_copy_str(g_discovered_vulns[g_vuln_count].binary_name, bin_name, sizeof(g_discovered_vulns[g_vuln_count].binary_name));
                        safe_copy_str(g_discovered_vulns[g_vuln_count].full_path, binary_path, sizeof(g_discovered_vulns[g_vuln_count].full_path));
                        g_discovered_vulns[g_vuln_count].payload = payload;
                        g_vuln_count++;
                    }
                } else {
                    printf("   ↳ Allowed: %s\n", binary_path);
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }
    pclose(fp);
    stop_spinner();
}
