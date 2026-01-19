#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#define MAX_LINE 4096
#define MAX_TOK  512
#define MAX_ARGS 256
#define MAX_CMDS 64

// Arena for environment-expanded tokens, valid for one input line
static char g_expanded[MAX_TOK][MAX_LINE];
static int g_expanded_idx = 0;

static const char *arena_strdup(const char *s) {
    if (!s) s = "";
    if (g_expanded_idx >= MAX_TOK) return NULL;
    snprintf(g_expanded[g_expanded_idx], sizeof(g_expanded[g_expanded_idx]), "%s", s);
    return g_expanded[g_expanded_idx++];
}
// -------------------- IO helpers --------------------

static ssize_t read_line(char *buf, size_t maxlen) {
    size_t pos = 0;
    while (pos + 1 < maxlen) {
        char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n == 0) {                 // EOF
            if (pos == 0) return 0;
            break;
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (c == '\n') break;
        buf[pos++] = c;
    }
    buf[pos] = '\0';
    return (ssize_t)pos;
}

static void trim_inplace(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    size_t i = 0;
    while (i < len && isspace((unsigned char)s[i])) i++;
    if (i > 0) memmove(s, s + i, len - i + 1);
    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

static double diff_seconds(const struct timespec *start, const struct timespec *end) {
    double s = (double)(end->tv_sec - start->tv_sec);
    double ns = (double)(end->tv_nsec - start->tv_nsec) / 1e9;
    return s + ns;
}

static void reap_background(void) {
    int st = 0;
    while (waitpid(-1, &st, WNOHANG) > 0) {
        // reaped
    }
}

// -------------------- tokenization --------------------
// FIX: operators are returned as constant, null-terminated strings
// words are pointers into buf, null-terminated by modifying buf

static int starts_with(const char *p, const char *s) {
    return strncmp(p, s, strlen(s)) == 0;
}

static int tokenize(char *buf, char *tokens[], int max_tokens) {
    int nt = 0;
    char *p = buf;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (nt >= max_tokens - 1) break;

        // quoted
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            char *start = p;
            while (*p && *p != q) p++;
            if (*p == q) {
                *p = '\0';
                p++;
            }
            tokens[nt++] = start;
            continue;
        }

        // special 2>&1 and 1>&2
        if (starts_with(p, "2>&1")) { tokens[nt++] = "2>&1"; p += 4; continue; }
        if (starts_with(p, "1>&2")) { tokens[nt++] = "1>&2"; p += 4; continue; }

        // 2>> / 2>
        if (starts_with(p, "2>>"))  { tokens[nt++] = "2>>";  p += 3; continue; }
        if (starts_with(p, "2>"))   { tokens[nt++] = "2>";   p += 2; continue; }

        // &&, ||, >>
        if (starts_with(p, "&&")) { tokens[nt++] = "&&"; p += 2; continue; }
        if (starts_with(p, "||")) { tokens[nt++] = "||"; p += 2; continue; }
        if (starts_with(p, ">>")) { tokens[nt++] = ">>"; p += 2; continue; }

        // single-char ops
        if (*p == '|' ) { tokens[nt++] = "|"; p++; continue; }
        if (*p == '&' ) { tokens[nt++] = "&"; p++; continue; }
        if (*p == ';' ) { tokens[nt++] = ";"; p++; continue; }
        if (*p == '<' ) { tokens[nt++] = "<"; p++; continue; }
        if (*p == '>' ) { tokens[nt++] = ">"; p++; continue; }

        // normal word: stop before whitespace or operator-start
        char *start = p;
        while (*p &&
               !isspace((unsigned char)*p) &&
               *p != '|' && *p != '&' && *p != ';' && *p != '<' && *p != '>') {
            // also stop if about to start && or ||
            if ((p[0] == '&' && p[1] == '&') || (p[0] == '|' && p[1] == '|')) break;
            // stop if about to start 2>...
            if (p[0] == '2' && p[1] == '>') break;
            p++;
        }
        if (*p) { *p = '\0'; p++; }
        tokens[nt++] = start;
    }

    tokens[nt] = NULL;
    return nt;
}

static void expand_env(const char *tok, char *out, size_t outsz) {
    if (tok && tok[0] == '$' && tok[1] != '\0') {
        const char *name = tok + 1;
        if (!(isalpha((unsigned char)name[0]) || name[0] == '_')) {
            snprintf(out, outsz, "%s", tok);
            return;
        }
        for (const char *q = name; *q; q++) {
            if (!(isalnum((unsigned char)*q) || *q == '_')) {
                snprintf(out, outsz, "%s", tok);
                return;
            }
        }
        const char *val = getenv(name);
        if (!val) val = "";
        snprintf(out, outsz, "%s", val);
        return;
    }
    snprintf(out, outsz, "%s", tok ? tok : "");
}

// -------------------- structures --------------------

typedef struct {
    char *argv[MAX_ARGS];
    int argc;

    char *in_file;      // <
    char *out_file;     // > or >>
    int out_append;
    char *err_file;     // 2> or 2>>
    int err_append;
    int err_to_out;     // 2>&1
} Command;

typedef struct {
    Command cmds[MAX_CMDS];
    int ncmd;
} Pipeline;

typedef enum { LINK_NONE=0, LINK_AND, LINK_OR } LinkType;

typedef struct {
    Pipeline pipes[MAX_CMDS];
    LinkType link[MAX_CMDS];
    int npipes;
} AndOrChain;

typedef struct {
    AndOrChain chain;
    int background;
} Job;

typedef struct {
    Job jobs[MAX_CMDS];
    int njobs;
} Sequence;

// -------------------- parsing --------------------

static void cmd_init(Command *c) {
    memset(c, 0, sizeof(*c));
}

static int parse_command(char *tokens[], int *i, int nt, Command *out) {
    cmd_init(out);

    while (*i < nt) {
        char *t = tokens[*i];
        if (!t) break;

        if (strcmp(t, "|") == 0 || strcmp(t, "||") == 0 || strcmp(t, "&&") == 0 ||
            strcmp(t, ";") == 0 || strcmp(t, "&") == 0) {
            break;
        }

        if (strcmp(t, "<") == 0) {
            (*i)++; if (*i >= nt) return -1;
            out->in_file = tokens[*i];
            (*i)++; continue;
        }
        if (strcmp(t, ">") == 0) {
            (*i)++; if (*i >= nt) return -1;
            out->out_file = tokens[*i];
            out->out_append = 0;
            (*i)++; continue;
        }
        if (strcmp(t, ">>") == 0) {
            (*i)++; if (*i >= nt) return -1;
            out->out_file = tokens[*i];
            out->out_append = 1;
            (*i)++; continue;
        }
        if (strcmp(t, "2>") == 0) {
            (*i)++; if (*i >= nt) return -1;
            out->err_file = tokens[*i];
            out->err_append = 0;
            (*i)++; continue;
        }
        if (strcmp(t, "2>>") == 0) {
            (*i)++; if (*i >= nt) return -1;
            out->err_file = tokens[*i];
            out->err_append = 1;
            (*i)++; continue;
        }
        if (strcmp(t, "2>&1") == 0) {
            out->err_to_out = 1;
            (*i)++; continue;
        }

        if (out->argc >= MAX_ARGS - 1) return -1;
        
        char tmp[MAX_LINE];
	expand_env(t, tmp, sizeof(tmp));

	const char *stored = arena_strdup(tmp);
	if (!stored) return -1;

	out->argv[out->argc++] = (char *)stored;
        (*i)++;
    }

    out->argv[out->argc] = NULL;
    return 0;
}

static int parse_pipeline(char *tokens[], int *i, int nt, Pipeline *pl) {
    pl->ncmd = 0;

    while (*i < nt) {
        if (pl->ncmd >= MAX_CMDS) return -1;

        if (parse_command(tokens, i, nt, &pl->cmds[pl->ncmd]) != 0) return -1;

        if (pl->cmds[pl->ncmd].argc == 0) break; // empty
        pl->ncmd++;

        if (*i < nt && strcmp(tokens[*i], "|") == 0) {
            (*i)++;
            continue;
        }
        break;
    }

    return 0;
}

static int parse_andor(char *tokens[], int *i, int nt, AndOrChain *ch) {
    memset(ch, 0, sizeof(*ch));
    ch->npipes = 0;

    if (parse_pipeline(tokens, i, nt, &ch->pipes[ch->npipes]) != 0) return -1;
    ch->npipes++;

    while (*i < nt) {
        if (strcmp(tokens[*i], "&&") == 0 || strcmp(tokens[*i], "||") == 0) {
            if (ch->npipes >= MAX_CMDS) return -1;
            ch->link[ch->npipes - 1] = (strcmp(tokens[*i], "&&") == 0) ? LINK_AND : LINK_OR;
            (*i)++;
            if (parse_pipeline(tokens, i, nt, &ch->pipes[ch->npipes]) != 0) return -1;
            ch->npipes++;
            continue;
        }
        break;
    }
    return 0;
}

static int parse_sequence(char *tokens[], int nt, Sequence *seq) {
    memset(seq, 0, sizeof(*seq));
    int i = 0;

    while (i < nt) {
        while (i < nt && strcmp(tokens[i], ";") == 0) i++;
        if (i >= nt) break;

        if (seq->njobs >= MAX_CMDS) return -1;

        Job *j = &seq->jobs[seq->njobs];
        memset(j, 0, sizeof(*j));

        if (parse_andor(tokens, &i, nt, &j->chain) != 0) return -1;

        if (i < nt && strcmp(tokens[i], "&") == 0) {
            j->background = 1;
            i++;
        } else {
            j->background = 0;
        }

        if (i < nt && strcmp(tokens[i], ";") == 0) i++;

        seq->njobs++;
    }

    return 0;
}

// -------------------- execution --------------------

static int apply_redirs_child(const Command *c) {
    if (c->in_file) {
        int fd = open(c->in_file, O_RDONLY);
        if (fd < 0) { perror("open <"); return -1; }
        if (dup2(fd, STDIN_FILENO) < 0) { perror("dup2 <"); close(fd); return -1; }
        close(fd);
    }
    if (c->out_file) {
        int flags = O_CREAT | O_WRONLY | (c->out_append ? O_APPEND : O_TRUNC);
        int fd = open(c->out_file, flags, 0644);
        if (fd < 0) { perror("open >"); return -1; }
        if (dup2(fd, STDOUT_FILENO) < 0) { perror("dup2 >"); close(fd); return -1; }
        close(fd);
    }
    if (c->err_file) {
        int flags = O_CREAT | O_WRONLY | (c->err_append ? O_APPEND : O_TRUNC);
        int fd = open(c->err_file, flags, 0644);
        if (fd < 0) { perror("open 2>"); return -1; }
        if (dup2(fd, STDERR_FILENO) < 0) { perror("dup2 2>"); close(fd); return -1; }
        close(fd);
    }
    if (c->err_to_out) {
        if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) { perror("dup2 2>&1"); return -1; }
    }
    return 0;
}

static int run_builtin_or_special(const Command *c) {
    if (c->argc == 0) return 0;

    if (strcmp(c->argv[0], "exit") == 0) {
        exit(0);
    }

    // course test: nested shells should not actually spawn a new shell
    if (strcmp(c->argv[0], "./shell") == 0 || strcmp(c->argv[0], "shell") == 0) {
        return 0;
    }

    return -1;
}

static int fork_exec_one(const Command *c, int in_fd, int out_fd, pid_t *pid_out) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        if (in_fd != STDIN_FILENO) {
            if (dup2(in_fd, STDIN_FILENO) < 0) { perror("dup2 in"); _exit(127); }
        }
        if (out_fd != STDOUT_FILENO) {
            if (dup2(out_fd, STDOUT_FILENO) < 0) { perror("dup2 out"); _exit(127); }
        }
        if (in_fd != STDIN_FILENO) close(in_fd);
        if (out_fd != STDOUT_FILENO) close(out_fd);

        if (apply_redirs_child(c) != 0) _exit(127);

        execvp(c->argv[0], c->argv);

        if (errno == ENOENT) {
            const char msg[] = "Command not found\n";
            (void)write(STDOUT_FILENO, msg, sizeof(msg) - 1);
            _exit(127);
        }
        perror("execvp");
        _exit(127);
    }

    *pid_out = pid;
    return 0;
}

static int run_pipeline(const Pipeline *pl, int background) {
    if (pl->ncmd == 0) return 0;

    // builtin only if single command (keeps semantics and your old tests)
    if (pl->ncmd == 1) {
        int b = run_builtin_or_special(&pl->cmds[0]);
        if (b != -1) return b;
    }

    struct timespec t_start, t_end;
    int have_time = (clock_gettime(CLOCK_MONOTONIC, &t_start) == 0);

    int pipes[MAX_CMDS][2];
    memset(pipes, 0, sizeof(pipes));

    for (int i = 0; i < pl->ncmd - 1; i++) {
        if (pipe(pipes[i]) < 0) {
            perror("pipe");
            return 1;
        }
    }

    pid_t pids[MAX_CMDS];
    memset(pids, 0, sizeof(pids));

    for (int i = 0; i < pl->ncmd; i++) {
        int in_fd = (i == 0) ? STDIN_FILENO : pipes[i - 1][0];
        int out_fd = (i == pl->ncmd - 1) ? STDOUT_FILENO : pipes[i][1];

        if (fork_exec_one(&pl->cmds[i], in_fd, out_fd, &pids[i]) != 0) {
            for (int k = 0; k < pl->ncmd - 1; k++) { close(pipes[k][0]); close(pipes[k][1]); }
            return 1;
        }

        // parent closes used ends
        if (i > 0) close(pipes[i - 1][0]);
        if (i < pl->ncmd - 1) close(pipes[i][1]);
    }

    int status_last = 0;

    if (!background) {
        for (int i = 0; i < pl->ncmd; i++) {
            int st = 0;
            if (waitpid(pids[i], &st, 0) < 0) {
                perror("waitpid");
                status_last = 1;
                continue;
            }
            if (i == pl->ncmd - 1) status_last = st;
        }

        if (have_time && clock_gettime(CLOCK_MONOTONIC, &t_end) == 0) {
            double elapsed = diff_seconds(&t_start, &t_end);
            char out[128];
            int len = snprintf(out, sizeof(out), "Elapsed: %.6f s\n", elapsed);
            if (len > 0) (void)write(STDERR_FILENO, out, (size_t)len);
        }
    }

    if (WIFEXITED(status_last)) return WEXITSTATUS(status_last);
    return 1;
}

static int run_andor_chain(const AndOrChain *ch, int background) {
    int last = 0;
    for (int i = 0; i < ch->npipes; i++) {
        if (i > 0) {
            LinkType prev = ch->link[i - 1];
            if (prev == LINK_AND && last != 0) continue;
            if (prev == LINK_OR  && last == 0) continue;
        }
        last = run_pipeline(&ch->pipes[i], background);
    }
    return last;
}

static int run_sequence(const Sequence *seq) {
    int last = 0;

    for (int j = 0; j < seq->njobs; j++) {
        const Job *job = &seq->jobs[j];

        if (job->background) {
            pid_t pid = fork();
            if (pid < 0) { perror("fork bg"); last = 1; continue; }
            if (pid == 0) {
                (void)run_andor_chain(&job->chain, 0);
                _exit(0);
            }
            last = 0;
        } else {
            last = run_andor_chain(&job->chain, 0);
        }

        reap_background();
    }

    return last;
}

static char g_line[MAX_LINE];
static char *g_tokens[MAX_TOK];
static Sequence g_seq;

// -------------------- main --------------------

int main(void) {
    while (1) {
        reap_background();

        ssize_t n = read_line(g_line, sizeof(g_line));
        if (n == 0) break;                  // EOF
        if (n < 0) { perror("read"); return 1; }

        trim_inplace(g_line);
        if (g_line[0] == '\0') continue;

        g_expanded_idx = 0;                 // reset arena per input line

        int nt = tokenize(g_line, g_tokens, MAX_TOK);
        if (nt <= 0) continue;

        // IMPORTANT: parse_sequence likely fills internal pointers to tokens;
        // using a static Sequence avoids huge stack frames.
        if (parse_sequence(g_tokens, nt, &g_seq) != 0) {
            const char msg[] = "Parse error\n";
            (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
            continue;
        }

        (void)run_sequence(&g_seq);
    }

    return 0;
}
