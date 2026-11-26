/* Linux container supervisor. The fixed entrypoint selects dotnet and the
 * agent assembly. Operator arguments reach the agent only after setpriv.
 * A dead listener reparents its armed watchdog here. Keep the PID namespace
 * alive until every descendant finishes, including during a graceful stop. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static bool has_agent_credentials(unsigned long long expected_caps)
{
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        real_uid != 1654 || effective_uid != 1654 || saved_uid != 1654 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_gid != 1654 || effective_gid != 1654 || saved_gid != 1654 ||
        getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        return false;

    FILE *status = fopen("/proc/self/status", "re");
    if (status == NULL)
        return false;
    const char *fields[] = {"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"};
    const size_t field_count = sizeof(fields) / sizeof(fields[0]);
    size_t matched = 0;
    char line[256];
    while (fgets(line, sizeof(line), status) != NULL) {
        for (size_t i = 0; i < field_count; i++) {
            size_t length = strlen(fields[i]);
            if (strncmp(line, fields[i], length) == 0) {
                unsigned long long bits;
                if (sscanf(line + length, "%llx", &bits) == 1 && bits == expected_caps)
                    matched++;
                break;
            }
        }
    }
    fclose(status);
    return matched == field_count;
}

/* Namespace PID 1 only receives signals it explicitly handles. Block these
 * before fork and consume them synchronously so a child exit cannot be lost. */
static void handle_signal(int number)
{
    (void)number;
}

static int supervise(char **command)
{
    sigset_t signals, original_mask;
    sigemptyset(&signals);
    const int watched[] = {SIGTERM, SIGINT, SIGCHLD};
    struct sigaction action = {.sa_handler = handle_signal};
    sigemptyset(&action.sa_mask);
    for (size_t i = 0; i < sizeof(watched) / sizeof(watched[0]); i++) {
        sigaddset(&signals, watched[i]);
        if (sigaction(watched[i], &action, NULL) == -1)
            return -1;
    }
    if (sigprocmask(SIG_BLOCK, &signals, &original_mask) == -1 ||
        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == -1)
        return -1;

    pid_t primary = fork();
    if (primary == -1)
        return -1;
    if (primary == 0) {
        if (sigprocmask(SIG_SETMASK, &original_mask, NULL) == 0)
            execv(command[0], command);
        perror("start agent");
        _exit(127);
    }

    int result = EXIT_FAILURE;
    for (;;) {
        int status;
        pid_t child = waitpid(-1, &status, WNOHANG);
        if (child > 0) {
            if (child == primary) {
                result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
                primary = 0;
            }
            continue;
        }
        if (child == -1)
            return errno == ECHILD ? result : -1;

        int received = sigwaitinfo(&signals, NULL);
        if (received == -1 && errno != EINTR)
            return -1;
        if (primary > 0 && (received == SIGTERM || received == SIGINT)) {
            if (kill(primary, received) == -1 && errno != ESRCH)
                return -1;
        }
    }
}

int main(int argc, char **argv)
{
    bool info = argc == 4 && (strcmp(argv[3], "--help") == 0 || strcmp(argv[3], "--version") == 0);
    if (argc < 3 || !has_agent_credentials(info ? 0 : 1ULL << CAP_NET_ADMIN)) {
        fputs("Agent requires the image entrypoint's restricted credentials.\n", stderr);
        return EXIT_FAILURE;
    }
    int result = supervise(&argv[1]);
    if (result < 0) {
        perror("supervise agent");
        return EXIT_FAILURE;
    }
    return result;
}
