CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O0

SRCDIR  = src
BINDIR  = bin

PROGS   = proc-fork shell_or cpu-calc-md5 ema-replace-int

all: $(addprefix $(BINDIR)/,$(PROGS))

$(BINDIR)/proc-fork: $(SRCDIR)/proc-fork.c
	$(CC) $(CFLAGS) -o $@ $<

$(BINDIR)/shell_or: $(SRCDIR)/mysh.c
	$(CC) $(CFLAGS) -o $@ $<

$(BINDIR)/cpu-calc-md5: $(SRCDIR)/cpu-calc-md5.c
	$(CC) $(CFLAGS) -o $@ $<

$(BINDIR)/ema-replace-int: $(SRCDIR)/ema-replace-int.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(addprefix $(BINDIR)/,$(PROGS))
