#include "../headers/spinner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static pthread_t g_spinner_thread;
static int g_spinner_running = 0;
static char g_spinner_msg[128];
static const char *braille_frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};

static void *spinner_loop(void *arg) {
    (void)arg;
    int idx = 0;
    while (g_spinner_running) {
        printf("\r\033[K[\033[0;35m%s\033[0m] %s", braille_frames[idx], g_spinner_msg);
        fflush(stdout);
        idx = (idx + 1) % 10;
        usleep(80000);
    }
    printf("\r\033[K");
    fflush(stdout);
    return NULL;
}

void start_spinner(const char *msg) {
    if (g_spinner_running) {
        stop_spinner();
    }
    strncpy(g_spinner_msg, msg, sizeof(g_spinner_msg) - 1);
    g_spinner_msg[sizeof(g_spinner_msg) - 1] = '\0';
    g_spinner_running = 1;
    pthread_create(&g_spinner_thread, NULL, spinner_loop, NULL);
}

void stop_spinner(void) {
    if (g_spinner_running) {
        g_spinner_running = 0;
        pthread_join(g_spinner_thread, NULL);
    }
}
