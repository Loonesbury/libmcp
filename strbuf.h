#ifndef LIBMCP_STRBUF_H
#define LIBMCP_STRBUF_H

typedef struct strbuf {
	char *str;
	int len;
	int size;
} strbuf;

/* 'minlen' is a desired starting capacity, not including the trailing NULL */
strbuf* sb_new(int minlen);
void    sb_free(strbuf *sb);
char*   sb_release(strbuf *sb);

void sb_concat(strbuf *sb, char *s);
void sb_addlen(strbuf *sb, int addlen);
void sb_reset(strbuf *sb);

#endif
