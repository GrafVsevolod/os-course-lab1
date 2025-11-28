// cpu-calc-md5.c
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define FRAG_COUNT    1024
#define FRAG_MIN_LEN  8
#define FRAG_MAX_LEN  64

typedef struct {
    uint32_t h[4];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buffer_len;
} md5_ctx;

static const uint32_t md5_k[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

static const uint8_t md5_s[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static void md5_init(md5_ctx *ctx) {
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xefcdab89u;
    ctx->h[2] = 0x98badcfeu;
    ctx->h[3] = 0x10325476u;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

static uint32_t rotl32(uint32_t x, uint8_t n) {
    return (x << n) | (x >> (32u - n));
}

static void md5_process_block(md5_ctx *ctx, const uint8_t block[64]) {
    uint32_t a = ctx->h[0];
    uint32_t b = ctx->h[1];
    uint32_t c = ctx->h[2];
    uint32_t d = ctx->h[3];

    uint32_t M[16];
    for (int i = 0; i < 16; ++i) {
        M[i] = (uint32_t)block[4*i] |
               ((uint32_t)block[4*i+1] << 8) |
               ((uint32_t)block[4*i+2] << 16) |
               ((uint32_t)block[4*i+3] << 24);
    }

    for (int i = 0; i < 64; ++i) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = (uint32_t)i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5u * i + 1u) & 0x0fu;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3u * i + 5u) & 0x0fu;
        } else {
            f = c ^ (b | ~d);
            g = (7u * i) & 0x0fu;
        }

        uint32_t tmp = d;
        d = c;
        c = b;
        uint32_t sum = a + f + md5_k[i] + M[g];
        b = b + rotl32(sum, md5_s[i]);
        a = tmp;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
}

static void md5_update(md5_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->buffer[ctx->buffer_len++] = data[i];
        ctx->bitlen += 8;
        if (ctx->buffer_len == 64) {
            md5_process_block(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void md5_final(md5_ctx *ctx, uint8_t out[16]) {
    uint64_t bitlen = ctx->bitlen;

    ctx->buffer[ctx->buffer_len++] = 0x80u;
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < 64) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        md5_process_block(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0;
    }

    for (int i = 0; i < 8; ++i) {
        ctx->buffer[56 + i] = (uint8_t)((bitlen >> (8u * i)) & 0xffu);
    }
    md5_process_block(ctx, ctx->buffer);

    for (int i = 0; i < 4; ++i) {
        out[4*i]     = (uint8_t)(ctx->h[i] & 0xffu);
        out[4*i + 1] = (uint8_t)((ctx->h[i] >> 8) & 0xffu);
        out[4*i + 2] = (uint8_t)((ctx->h[i] >> 16) & 0xffu);
        out[4*i + 3] = (uint8_t)((ctx->h[i] >> 24) & 0xffu);
    }
}

static char *fragments[FRAG_COUNT];
static size_t frag_len[FRAG_COUNT];

static void free_fragments(void) {
    for (int i = 0; i < FRAG_COUNT; ++i) {
        free(fragments[i]);
        fragments[i] = NULL;
        frag_len[i] = 0;
    }
}

static void generate_fragments(unsigned int seed) {
    srand(seed);
    for (int i = 0; i < FRAG_COUNT; ++i) {
        size_t len = FRAG_MIN_LEN +
                     (size_t)(rand() % (FRAG_MAX_LEN - FRAG_MIN_LEN + 1));
        char *buf = malloc(len);
        if (!buf) {
            perror("malloc");
            free_fragments();
            exit(EXIT_FAILURE);
        }
        for (size_t j = 0; j < len; ++j) {
            int r = rand() % 26;
            buf[j] = (char)('a' + r);
        }
        fragments[i] = buf;
        frag_len[i] = len;
    }
}

static long parse_long(const char *arg, const char *name) {
    char *end = NULL;
    errno = 0;
    long v = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || v <= 0) {
        fprintf(stderr, "Invalid value for %s: '%s'\n", name, arg);
        exit(EXIT_FAILURE);
    }
    return v;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s --repeats N [--seed S]\n\n"
            "  --repeats N   Number of fragments to feed into MD5.\n"
            "  --seed S      RNG seed (default: 42).\n",
            prog);
}

int main(int argc, char **argv) {
    long repeats = -1;
    unsigned int seed = 42u;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--repeats") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--repeats requires value\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            repeats = parse_long(argv[++i], "--repeats");
        } else if (strncmp(argv[i], "--repeats=", 10) == 0) {
            repeats = parse_long(argv[i] + 10, "--repeats");
        } else if (strcmp(argv[i], "--seed") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--seed requires value\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            long s = parse_long(argv[++i], "--seed");
            seed = (unsigned int)s;
        } else if (strncmp(argv[i], "--seed=", 7) == 0) {
            long s = parse_long(argv[i] + 7, "--seed");
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

    if (repeats <= 0) {
        fprintf(stderr, "You must specify --repeats > 0\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    generate_fragments(seed ^ 0x12345678u);
    srand(seed);

    md5_ctx ctx;
    md5_init(&ctx);

    for (long i = 0; i < repeats; ++i) {
        int idx = rand() % FRAG_COUNT;
        md5_update(&ctx, (const uint8_t *)fragments[idx], frag_len[idx]);
    }

    uint8_t digest[16];
    md5_final(&ctx, digest);

    for (int i = 0; i < 16; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    free_fragments();
    return 0;
}
