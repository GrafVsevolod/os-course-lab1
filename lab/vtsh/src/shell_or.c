#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#define MAX_LINE 4096
#define MAX_ARGS 128

static ssize_t read_line(char *buf, size_t maxlen) {
    size_t pos = 0;

    while (pos + 1 < maxlen) {
        char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n == 0) {

            if (pos == 0) {
                return 0;
            }
            break; 
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (c == '\n') {
            break;
        }
        buf[pos++] = c;
    }

    buf[pos] = '\0';
    return (ssize_t)pos;
}

static void trim(char **pstr) {
    char *s = *pstr;
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        *pstr = s;
        return;
    }
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    *pstr = s;
}

static int build_argv(char *cmd, char **argv, int max_args) {
    int argc = 0;
    char *p = cmd;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) {
            p++;
        }
        if (!*p) {
            break;
        }
        if (argc >= max_args - 1) {
            break;
        }
        argv[argc++] = p;
        while (*p && !isspace((unsigned char)*p)) {
            p++;
        }
        if (*p) {
            *p = '\0';
            p++;
        }
    }
    argv[argc] = NULL;
    return argc;
}

static double diff_seconds(const struct timespec *start, const struct timespec *end) {
    double s = (double)(end->tv_sec - start->tv_sec);
    double ns = (double)(end->tv_nsec - start->tv_nsec) / 1e9;
    return s + ns;
}

static int run_single_command(char *cmd) {
    char *argv[MAX_ARGS];

    trim(&cmd);
    if (*cmd == '\0') {
        return 0;
    }

    int argc = build_argv(cmd, argv, MAX_ARGS);
    if (argc == 0 || argv[0] == NULL) {
        return 0;
    }

    if (strcmp(argv[0], "exit") == 0) {
        exit(0);
    }

    if (strcmp(argv[0], "./shell") == 0 || strcmp(argv[0], "shell") == 0) {
        return 0;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    struct timespec t_start, t_end;
    if (clock_gettime(CLOCK_MONOTONIC, &t_start) != 0) {
        perror("clock_gettime");
        // не выходим — просто не меряем время, но команда должна выполниться
    }

    if (pid == 0) {
        execvp(argv[0], argv);

        if (errno == ENOENT) {
            const char msg[] = "Command not found\n";
            ssize_t unused = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
            (void)unused;
            _exit(127);
        } else {
            perror("execvp");
            _exit(127);
        }
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &t_end) == 0) {
        double elapsed = diff_seconds(&t_start, &t_end);
        char out[128];
        int len = snprintf(out, sizeof(out), "Elapsed: %.6f s\n", elapsed);
        if (len > 0) {
            (void)write(STDERR_FILENO, out, (size_t)len);
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return 1;
}

int main(void) {
    char line[MAX_LINE];

    for (;;) {
        ssize_t n = read_line(line, sizeof(line));
        if (n == 0) {
            // EOF
            break;
        }
        if (n < 0) {
            perror("read");
            return 1;
        }

        run_single_command(line);
    }

    return 0;
}



