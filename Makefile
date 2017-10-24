ifeq ($(OS),Windows_NT)
	RM=del
	EXT=dll
else
	RM=rm
	EXT=so
endif

CC=gcc
DEPFLAGS=-c
CFLAGS=-g -fPIC -Wall -Wpedantic
LFLAGS=-g -shared
SRC=mcp.c strbuf.c aa.c
OBJ=$(SRC:%.c=%.o)
OUTFILE=libmcp.$(EXT)

main: $(OBJ)
	$(CC) $(LFLAGS) -o $(OUTFILE) $(OBJ)

$(OBJ): %.o: %.c
	@$(CC) $(DEPFLAGS) -o $@ -MMD $<
	$(CC) $(CFLAGS) -c $< -o $@

-include *.d

clean:
	@$(RM) $(OUTFILE)
	@$(RM) $(OBJ)
	@$(RM) *.d
