#include <stdlib.h>
#include <string.h>
#include "strbuf.h"

strbuf* sb_new(int minlen)
{
	strbuf *sb = memset(malloc(sizeof(strbuf)), 0, sizeof(strbuf));
	if (minlen) {
		sb->size = minlen + 1;
		sb->str  = memset(malloc(minlen + 1), 0, minlen + 1);
	}
	return sb;
}

void sb_free(strbuf *sb)
{
	if (sb->str)
		free(sb->str);
	free(sb);
}

char* sb_release(strbuf *sb)
{
	char *str = sb->str;
	free(sb);
	return str;
}

void sb_concat(strbuf *sb, char *s)
{
	int len = strlen(s);
	sb_addlen(sb, len);
	memcpy(sb->str + sb->len, s, len);
	sb->len += len;
}

void sb_addlen(strbuf *sb, int addlen)
{
	unsigned int sz;
	/* +1 for NULL */
	if (!sb->size)
		addlen++;
	if (sb->len + addlen <= sb->size)
		return;
	/* Next-power-of-2 by Sean Anderson */
	/* if already a power of 2, value remains the same */
	sz = sb->len + addlen;
	sz--;
	sz |= sz >> 1;
	sz |= sz >> 2;
	sz |= sz >> 4;
	sz |= sz >> 8;
	sz |= sz >> 16;
	sz++;
	sb->size = sz;
	sb->str = realloc(sb->str, sb->size);
}

void sb_reset(strbuf *sb)
{
	if (sb->str)
		free(sb->str);
	sb->str = NULL;
	sb->size = sb->len = 0;
}
