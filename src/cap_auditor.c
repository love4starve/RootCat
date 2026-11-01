#include "../headers/cap_auditor.h"
#include "../headers/exploit.h"
#include "../headers/spinner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

static void safe_copy_str(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

void audit_capabilities(int verbose) {
    (void)verbose;
    start_spinner("scanning capabilities...");

    FILE *fp = popen("getcap -r / 2>/dev/null", "r");
    if (!fp) {
        stop_spinner();
        return;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp)) {
        char *eq_ptr = strchr(buffer, '=');
        if (!eq_ptr) continue;

        *eq_ptr = '\0';
        char *binary_path = buffer;
        char *cap_spec = eq_ptr + 1;

        while (isspace((unsigned char)*binary_path)) binary_path++;
        char *end = binary_path + strlen(binary_path) - 1;
        while (end > binary_path && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }

        if (strstr(cap_spec, "cap_setuid") || strstr(cap_spec, "cap_dac_override") || strstr(cap_spec, "cap_sys_admin")) {
            char *bin_name = strrchr(binary_path, '/');
            if (bin_name) bin_name++;
            else bin_name = binary_path;

            const GTFOBinPayload *payload = find_gtfobin_payload(bin_name);
            if (payload) {
                stop_spinner();
                printf("[\033[1;31m+\033[0m] Capability vulnerability: %s (%s)\n", binary_path, cap_spec);
                if (g_vuln_count < MAX_DISCOVERED_VULNS) {
                    safe_copy_str(g_discovered_vulns[g_vuln_count].binary_name, bin_name, sizeof(g_discovered_vulns[g_vuln_count].binary_name));
                    safe_copy_str(g_discovered_vulns[g_vuln_count].full_path, binary_path, sizeof(g_discovered_vulns[g_vuln_count].full_path));
                    g_discovered_vulns[g_vuln_count].payload = payload;
                    g_vuln_count++;
                }
                start_spinner("scanning capabilities...");
            }
        }
    }
    pclose(fp);
    stop_spinner();
}
