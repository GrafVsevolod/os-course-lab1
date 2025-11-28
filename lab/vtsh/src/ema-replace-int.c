// ema-replace-int.c
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  Generate file of int32_t values:\n"
            "    %s --generate FILE SIZE_MB [--seed S]\n\n"
            "  Replace values in existing file:\n"
            "    %s --file FILE --from A --to B --repeats N\n\n",
            prog, prog);
}

static long parse_long(const char *arg, const char *name) {
    char *end = NULL;
    errno = 0;
    long v = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: '%s'\n", name, arg);
        exit(EXIT_FAILURE);
    }
    return v;
}

static void generate_file(const char *path, long size_mb, unsigned int seed) {
    if (size_mb <= 0) {
        fprintf(stderr, "SIZE_MB must be > 0\n");
        exit(EXIT_FAILURE);
    }
    uint64_t total_bytes = (uint64_t)size_mb * 1024u * 1024u;
    uint64_t total_ints = total_bytes / sizeof(int32_t);
    if (total_ints == 0) {
        fprintf(stderr, "SIZE_MB too small for at least one int32_t\n");
        exit(EXIT_FAILURE);
    }

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        perror("open for generate");
        exit(EXIT_FAILURE);
    }

    srand(seed);
    const size_t buf_count = 4096;
    int32_t *buf = malloc(buf_count * sizeof(int32_t));
    if (!buf) {
        perror("malloc");
        close(fd);
        exit(EXIT_FAILURE);
    }

    uint64_t written = 0;
    while (written < total_ints) {
        size_t chunk = buf_count;
        if (total_ints - written < chunk) {
            chunk = (size_t)(total_ints - written);
        }
        for (size_t i = 0; i < chunk; ++i) {
            buf[i] = (int32_t)(rand() % 1000000); // ограниченный диапазон
        }
        size_t bytes = chunk * sizeof(int32_t);
        ssize_t w = write(fd, buf, bytes);
        if (w < 0) {
            perror("write");
            free(buf);
            close(fd);
            exit(EXIT_FAILURE);
        }
        if ((size_t)w != bytes) {
            fprintf(stderr, "Short write\n");
            free(buf);
            close(fd);
            exit(EXIT_FAILURE);
        }
        written += chunk;
    }

    free(buf);
    if (close(fd) < 0) {
        perror("close");
        exit(EXIT_FAILURE);
    }
}

static void replace_values(const char *path, int32_t from, int32_t to, long repeats) {
    if (repeats <= 0) {
        fprintf(stderr, "--repeats must be > 0\n");
        exit(EXIT_FAILURE);
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (st.st_size == 0) {
        fprintf(stderr, "File is empty\n");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (st.st_size % (off_t)sizeof(int32_t) != 0) {
        fprintf(stderr, "File size is not multiple of int32_t\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    size_t count = (size_t)(st.st_size / (off_t)sizeof(int32_t));

    void *addr = mmap(NULL, (size_t)st.st_size,
                      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(EXIT_FAILURE);
    }

    int32_t *data = (int32_t *)addr;

    for (long r = 0; r < repeats; ++r) {
        size_t replaced = 0;
        for (size_t i = 0; i < count; ++i) {
            if (data[i] == from) {
                data[i] = to;
                ++replaced;
            }
        }
        fprintf(stderr, "Repeat %ld: replaced %zu values\n", r + 1, replaced);
    }

    if (msync(addr, (size_t)st.st_size, MS_SYNC) < 0) {
        perror("msync");
    }

    if (munmap(addr, (size_t)st.st_size) < 0) {
        perror("munmap");
    }

    if (close(fd) < 0) {
        perror("close");
    }
}

int main(int argc, char **argv) {
    const char *file = NULL;
    long size_mb = -1;
    unsigned int seed = 42u;
    int have_generate = 0;

    int have_replace = 0;
    int32_t from = 0;
    int32_t to = 0;
    long repeats = -1;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--generate") == 0) {
            if (i + 2 >= argc) {
                fprintf(stderr, "--generate FILE SIZE_MB\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            file = argv[++i];
            size_mb = parse_long(argv[++i], "SIZE_MB");
            have_generate = 1;
        } else if (strcmp(argv[i], "--file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--file requires value\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            file = argv[++i];
            have_replace = 1;
        } else if (strcmp(argv[i], "--from") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--from requires value\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            from = (int32_t)parse_long(argv[++i], "--from");
            have_replace = 1;
        } else if (strcmp(argv[i], "--to") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--to requires value\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            to = (int32_t)parse_long(argv[++i], "--to");
            have_replace = 1;
        } else if (strcmp(argv[i], "--repeats") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--repeats requires value\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            repeats = parse_long(argv[++i], "--repeats");
            have_replace = 1;
        } else if (strcmp(argv[i], "--seed") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--seed requires value\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            long s = parse_long(argv[++i], "--seed");
            seed = (unsigned int)s;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (have_generate && have_replace) {
        fprintf(stderr, "Use either generate mode or replace mode, not both.\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (have_generate) {
        if (!file || size_mb <= 0) {
            fprintf(stderr, "Generate mode requires FILE and SIZE_MB > 0\n");
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        generate_file(file, size_mb, seed);
        return EXIT_SUCCESS;
    }

    if (have_replace) {
        if (!file || repeats <= 0) {
            fprintf(stderr, "Replace mode requires --file and --repeats > 0\n");
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        replace_values(file, from, to, repeats);
        return EXIT_SUCCESS;
    }

    fprintf(stderr, "You must specify either generate or replace mode.\n");
    usage(argv[0]);
    return EXIT_FAILURE;
}
