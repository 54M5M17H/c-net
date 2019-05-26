# See http://nuclear.mutantstargoat.com/articles/make/

CC=gcc

src = $(wildcard src/**/*.c) \
		$(wildcard src/main.c)

obj = $(src:.c=.o)
dep = $(obj:.o=.d)  # one dependency file for each source

cnet: $(obj)
		$(CC) -o $@ $^ $(CFLAGS)

# -include $(dep)   # include all dep files in the makefile

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
# %.d: %.c
# 		cpp $< -M -MT $(@:.d=.o) >$@

# .PHONY: clean
# clean:
# 		rm -f $(obj) cnet

# .PHONY: cleandep
# cleandep:
# 		rm -f $(dep)
