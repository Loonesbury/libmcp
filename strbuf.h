#ifndef LIBMCP_STRBUF_H
#define LIBMCP_STRBUF_H

typedef struct strbuf {
	char *str;
	int len;
	int size;
} strbuf;

strbuf* sb_new();
void    sb_free(strbuf *sb);
char*   sb_release(strbuf *sb);

void sb_concat(strbuf *sb, char *s);
void sb_addlen(strbuf *sb, int addlen);
void sb_reset(strbuf *sb);

#endif
