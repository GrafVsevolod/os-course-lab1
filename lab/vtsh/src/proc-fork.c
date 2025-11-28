#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static void
print_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s --repeats N\n", progname);
}


static int
parse_positive_long(const char *arg, long *out)
{
    char *endptr = NULL;
    errno = 0;
    long val = strtol(arg, &endptr, 10);

    if (errno != 0 || endptr == arg || *endptr != '\0') {
        return -1;
    }
    if (val <= 0) {
        return -1;
    }

    *out = val;
    return 0;
}

int
main(int argc, char *argv[])
{
    long repeats = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--repeats") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --repeats\n");
                print_usage(argv[0]);
                return 2; 
            }
            if (parse_positive_long(argv[i + 1], &repeats) != 0) {
                fprintf(stderr, "Invalid value for --repeats: %s\n", argv[i + 1]);
                print_usage(argv[0]);
                return 2;
            }
            ++i;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (repeats <= 0) {
        fprintf(stderr, "Required option --repeats N (N > 0)\n");
        print_usage(argv[0]);
        return 2;
    }

    for (long i = 0; i < repeats; ++i) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }

        if (pid == 0) {
            _exit(0);
        }

        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            return 1;
        }
    }

    return 0;
}
