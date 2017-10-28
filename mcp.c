#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#endif
#include "mcp.h"
#include "aa.h"
#include "strbuf.h"

/* sets 'ret' to the current token and null-terminates it */
/* then skips whitespace afterward */
#define ADVANCE(ret, s)\
{\
	ret = s;\
	while (*s && *s != ' ') s++;\
	if (*s)\
		*s++ = '\0';\
	SKIP_WS(s);\
}
#define SKIP_WS(s) { while (*s == ' ') s++; }

static char *str_dup(char *s)
{
	int sz = strlen(s) + 1;
	return memcpy(malloc(sz), s, sz);
}

static char* str_lower(char *s)
{
	char *p = s;
	while (*p) {
		*p = tolower(*p);
		p++;
	}
	return s;
}

/* checks if 's' is a valid keyword */
static int valid_ident(char *s)
{
	char c = *s++;
	if (!isalpha(c) && c != '_')
		return 0;
	while ((c = *s++)) {
		if (!isalnum(c) && c != '_' && c != '-')
			return 0;
	}
	return 1;
}

/* checks if 's' is a valid simple (unquoted) string */
/* this is also used for authentication keys and _data-tags */
static int valid_unquoted(char *s)
{
	return !strpbrk(s, "\"*\\: ");
}

typedef struct McpArg {
	int multi;
	union {
		char *str;
		strbuf *buf;
	} val;
} McpArg;

static McpArg* mcp_newarg(char *s, int multi)
{
	McpArg *arg = malloc(sizeof(McpArg));
	arg->multi = multi;
	if (multi) {
		strbuf *sb = sb_new(256);
		sb->str = str_dup(s);
		sb->len = strlen(s);
		sb->size = sb->len + 1;
		arg->val.buf = sb;
	} else {
		arg->val.str = str_dup(s);
	}
	return arg;
}

static void mcp_freearg(void *val)
{
	McpArg *arg = (McpArg*)val;
	if (arg->multi)
		sb_free(arg->val.buf);
	else
		free(arg->val.str);
	free(arg);
}

static void foreach_args(aa_node *n, void *unused)
{
	McpArg *arg = (McpArg*)n->val;
	if (arg->multi) {
		/* replace trailing '\n' with a terminator */
		/* XXX: this is pretty terrible */
		strbuf *sb = arg->val.buf;
		sb->str[sb->len - 1] = '\0';
		n->val = (void*)sb_release(arg->val.buf);
	} else {
		n->val = (void*)arg->val.str;
	}
	free(arg);
}

int ver_check(int low, int high, int min, int max)
{
	if (high >= min && max >= low)
		return (high > max) ? max : high;
	return 0;
}

int ver_get(McpMessage *msg, char *key)
{
	char *s = mcp_getarg(msg, key), *n = s;
	int ver = 0;
	if (!s || !isdigit(*s))
		return -1;
	ver += strtol(s, &n, 10)*1000;
	if (!n || n == s || n[0] != '.' || !isdigit(n[1]))
		return -1;
	ver += strtol(n + 1, &n, 10);
	if (!n || !*n)
		return ver;
	return -1;
}

char* ver_tostr(int ver, char *str, int sz)
{
	snprintf(str, sz, "%i.%i", ver/1000, ver % 1000);
	return str;
}

static void foreach_pkgs(aa_node *n, void *arg)
{
	char vmin[16], vmax[16];
	McpState *mcp = (McpState*)arg;
	McpPackage *pkg = ((McpPackageInfo*)n->val)->pkg;

	ver_tostr(pkg->minver, vmin, sizeof(vmin));
	ver_tostr(pkg->maxver, vmax, sizeof(vmin));

	mcp_send(mcp, "mcp-negotiate-can", 3,
		"package", pkg->name,
		"min-version", vmin,
		"max-version", vmax
	);
}

/* this is a builtin because reasons */
static int mcpfn_mcp(McpState *mcp, McpMessage *msg)
{
	/* our supported version */
	int min, max;
	/* their supported version */
	int from, to;

	/* already received 'mcp'? */
	if (mcp->version != 0)
		return MCP_ERROR;

	min  = max = MCP_VERSION(2, 1);
	from = ver_get(msg, "version");
	to   = ver_get(msg, "to");
	if (from < 0 || to < 0) {
		/* the standard doesn't say that 0.0 is an illegal version */
		/* so we only halt for malformed numbers */
		mcp->version = -1;
		return MCP_ERROR;
	}

	mcp->version = ver_check(from, to, min, max);
	if (!mcp->version)
		/* not technically an error */
		return MCP_OK;

	if (mcp->server) {
		/* server gets authkey from client */
		char *authkey = mcp_getarg(msg, "authentication-key");
		if (!valid_unquoted(authkey)) {
			mcp->version = -1;
			return MCP_ERROR;
		}
		mcp->authkey = str_dup(authkey);
	} else {
		mcp_send(mcp, "mcp", 3,
			"version", "2.1",
			"to", "2.1",
			"authentication-key", mcp->authkey
		);
	}

	/* both sides send packages */
	aa_foreach(mcp->pkgs, &foreach_pkgs, mcp);
	/* mcp-negotiate 1.0 doesn't recognize 'end', but it should be */
	/* safely ignored by a compliant implementation */
	mcp_send(mcp, "mcp-negotiate-end", 0);

	return MCP_OK;
}

McpFuncInfo* mcp_wrapfn(McpFunc fn, McpPackageInfo *info)
{
	McpFuncInfo *h = memset(malloc(sizeof(McpFuncInfo)), 0, sizeof(McpFuncInfo));
	h->fn = fn;
	h->info = info;
	return h;
}

/* XXX: awful kludges to suppress warnings about incompatible pointer types */
static void aa_free_(void *t) {
	aa_free((aa_tree*)t);
}

McpState* mcp_newclient(McpSendFunc sendfn, char *authkey)
{
	McpState *mcp = malloc(sizeof(McpState));
	memset(mcp, 0, sizeof(McpState));

	if (authkey && *authkey)
		mcp->authkey = str_dup(authkey);
	mcp->send = sendfn;
	mcp->handlers = aa_new(&free);
	mcp->mlines = aa_new(&aa_free_);
	mcp->pkgs = aa_new(&free);

	aa_insert(mcp->handlers, "mcp", mcp_wrapfn(&mcpfn_mcp, NULL));

	return mcp;
}

McpState* mcp_newserver(McpSendFunc sendfn, void *data)
{
	McpState *mcp = mcp_newclient(sendfn, NULL);
	mcp->server = 1;
	mcp->data = data;
	return mcp;
}

void mcp_free(McpState *mcp)
{
	free(mcp->authkey);
	/* does not free packages, just our handles to them */
	aa_free(mcp->pkgs);
	aa_free(mcp->handlers);
	aa_free(mcp->mlines);
	free(mcp);
}

static int handle_msg(McpState *mcp, char *name, aa_tree *args)
{
	static McpMessage msg;
	McpFuncInfo *h;

	if (strcmp(name, "mcp") && mcp->version <= 0)
		return MCP_ERROR;

	h = (McpFuncInfo*)aa_get(mcp->handlers, name);

	msg.name = name;
	msg.args = args;
	msg.info = h->info;

	assert(h != NULL);
	return h->fn(mcp, &msg);
}

int mcp_parse(McpState *mcp, char *buf)
{
	int len = strlen(buf), multi = 0, rv;
	char *name, *authkey, *argk, *argv;
	char *b = buf + 3, *bend = buf + len;
	aa_tree *args;

	/* if it's escaped, wipe out the escape and pass it back */
	if (!strncmp(buf, "#$\"", 3)) {
		memmove(buf + 3, buf, len + 1);
		return MCP_NONE;
	}
	if (strncmp(buf, "#$#", 3))
		return MCP_NONE;

	ADVANCE(name, b);
	if (!*name)
		return MCP_ERROR;
	str_lower(name);

	/* weird juggling because 'mcp' doesn't include an auth key */
	if (strcmp(name, "mcp")) {
		ADVANCE(authkey, b);
		if (!valid_unquoted(authkey))
			return MCP_ERROR;
	}

	/* continue a multi-line argument */
	if (!strcmp(name, "*")) {
		McpArg *arg;

		args = (aa_tree*)aa_get(mcp->mlines, authkey);
		if (!args)
			return MCP_ERROR;

		/* wow! this is terrible! */
		argk = b;
		while (1) {
			char c = *b;
			if (!c) {
				aa_remove(mcp->mlines, authkey);
				return MCP_ERROR;
			}
			if (c == ':')
				break;
			*b++ = tolower(c);
		}
		*b++ = '\0';

		if (!valid_ident(argk) || *b != ' ') {
			/* bad identifier, or no delimiter afterward */
			aa_remove(mcp->mlines, authkey);
			return MCP_ERROR;
		}
		b++;

		arg = (McpArg*)aa_get(args, argk);
		if (!arg || !arg->multi) {
			aa_remove(mcp->mlines, authkey);
			return MCP_ERROR;
		}
		if (*b)
			sb_concat(arg->val.buf, b);
		sb_concat(arg->val.buf, "\n");

		return MCP_OK;
	}

	/* finish multi-line message */
	if (!strcmp(name, ":")) {
		args = (aa_tree*)aa_get(mcp->mlines, authkey);
		if (!args)
			return MCP_ERROR;

		name = ((McpArg*)aa_get(args, "*name*"))->val.str;
		assert(name != NULL);

		/* ARGH ARGH ARGH */
		aa_foreach(args, &foreach_args, NULL);
		args->freeval = &free;

		rv = handle_msg(mcp, name, args);
		aa_remove(mcp->mlines, authkey);
		return rv;
	}

	if (strcmp(name, "mcp")) {
		/* hooray for 'mcp' and its ~special~ syntax */
		if (strcmp(authkey, mcp->authkey))
			return MCP_ERROR;
	}

	if (!aa_get(mcp->handlers, name))
		return MCP_ERROR;

	args = aa_new(&mcp_freearg);

	/* parse key-val arguments */
	while (b < bend) {
		int multiarg = 0;
		argk = b;

		while (1) {
			char c = *b;
			if (c == ':')
				break;
			if (c == '*') {
				*b++ = '\0';
				if (*b == ':') {
					multiarg = 1;
					break;
				} else {
					aa_free(args);
					return MCP_ERROR;
				}
			}
			if (c == '\0' || c == ' ' || c == '\\' || c == '"') {
				aa_free(args);
				return MCP_ERROR;
			}
			b++;
		}
		*b++ = '\0';

		SKIP_WS(b);

		if (*b == '"') {
			/* copy chars backward to deal with escaped chars */
			char *write = argv = ++b;
			char escaped = 0;

			while (1) {
				char c = *b;
				if (!c) {
					/* EOF while reading string */
					aa_free(args);
					return MCP_ERROR;
				}

				if (escaped || (c != '\\' && c != '"')) {
					escaped = 0;
					*write++ = c;
				} else if (c == '\\') {
					escaped = 1;
				} else {
					break;
				}
				b++;
			}
			*write++ = '\0';
			b++;
		} else {
			argv = b;
			while (1) {
				char c = *b;
				if (c == ' ' || c == '\0')
					break;
				if (c == '\\' || c == '"' || c == '*' || c == ':') {
					/* invalid letters in unquoted string */
					aa_free(args);
					return MCP_ERROR;
				}
				b++;
			}
			*b++ = '\0';
		}

		if (aa_get(args, argk) != NULL) {
			aa_free(args);
			return MCP_ERROR;
		}

		if (multiarg)
			multi = 1;
		aa_insert(args, argk, mcp_newarg(argv, multiarg));

		SKIP_WS(b);
	}

	if (multi) {
		/* got a multi-line key around here somewhere. */
		McpArg *tag = (McpArg*)aa_get(args, "_data-tag");
		if (tag == NULL || tag->multi || !valid_unquoted(tag->val.str)) {
			/* or not. */
			aa_free(args);
			return MCP_ERROR;
		}

		aa_insert(args, "*name*", mcp_newarg(name, 0));
		aa_insert(mcp->mlines, tag->val.str, args);
		return MCP_OK;
	}

	/* ARGH ARGH ARGH */
	aa_foreach(args, &foreach_args, NULL);
	args->freeval = &free;

	rv = handle_msg(mcp, name, args);
	aa_free(args);
	return rv;
}

typedef struct bufinfo {
	char *buf, *s, *e;
	int err;
} bufinfo;

int cat_buf(bufinfo *b, char *fmt, ...)
{
	int szleft = b->e - b->s;
	int ct;
	va_list args;

	assert(szleft > 0);
	if (b->err)
		return 0;

	va_start(args, fmt);
	ct = vsnprintf(b->s, szleft, fmt, args);
	va_end(args);

	if (ct < 0 || ct >= szleft) {
		b->err = 1;
		return 0;
	}
	b->s += ct;
	return 1;
}

static void count_args(aa_node *n, void *arg)
{
	*((int*)arg) += 3 + strlen(n->key) + strlen(n->val);
}

static void cat_args(aa_node *n, void *arg)
{
	bufinfo *b = (bufinfo*)arg;
	if (!valid_ident(n->key))
		b->err = 2;
	if (b->err)
		return;
	cat_buf(b, " %s: %s", n->key, (char*)n->val);
}

int mcp_sendmsg(McpState *mcp, McpMessage *msg)
{
	struct bufinfo b;
	int ok, ismcp = !strcmp(msg->name, "mcp");
	int len = 3 + strlen(msg->name);

	if (!mcp_supports(mcp, msg->name))
		return 0;

	if (!ismcp)
		len += 1 + strlen(mcp->authkey);

	aa_foreach(msg->args, &count_args, &len);

	b.s = b.buf = malloc(len + 1);
	b.e = b.s + len + 1;
	b.err = 0;

	if (ismcp) {
		ok = cat_buf(&b, "#$#mcp");
	} else {
		ok = cat_buf(&b, "#$#%s %s", msg->name, mcp->authkey);
	}
	assert(ok);
	aa_foreach(msg->args, &cat_args, &b);
	if (b.err == 2) {
		free(b.buf);
		return 0;
	}
	assert(!b.err);
	assert(b.s + 1 == b.e);

	mcp->send(mcp->data, b.buf);
	free(b.buf);

	return 1;
}

static unsigned int get_rand()
{
	unsigned int n;
#ifdef _WIN32
	/* XXX: 'implicit declaration' warning with MinGW gcc, but links OK */
	if (rand_s(&n))
		return rand();
#else
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return rand();
	if (read(fd, &n, sizeof(n)) < 0)
		return rand();
#endif
	return n;
}

int mcp_send(McpState *mcp, char *name, int nkeys, ...)
{
	aa_tree *args;
	va_list argp;
	int ismcp = !strcmp(name, "mcp");
	int i, m = 0, multilen = 0;
	char *key, *val, *multi[512];
	strbuf *sb;

	if (!mcp_supports(mcp, name))
		return 0;

	sb = sb_new(511);
	sb_concat(sb, "#$#");
	sb_concat(sb, name);
	if (!ismcp) {
		sb_concat(sb, " ");
		sb_concat(sb, mcp->authkey);
	}

	args = aa_new(NULL);
	va_start(argp, nkeys);

	for (i = 0; i < nkeys; i++) {
		key = va_arg(argp, char*);

		if (!valid_ident(key)) {
			sb_free(sb);
			va_end(argp);
			aa_free(args);
			return 0;
		} else if (aa_has(args, key)) {
			va_arg(argp, char*);
			continue;
		}

		val = va_arg(argp, char*);
		sb_concat(sb, " ");
		sb_concat(sb, key);

		if (strchr(val, '\n') != NULL) {
			/* arg is multi-line - store it and deal with it afterward */
			char *v = val, *vend = val + strlen(val);
			int klen = strlen(key), sublen = -1;
			while (v < vend) {
				/* argh argh argh */
				sublen = strcspn(v, "\n");
				if (klen + sublen > multilen)
					multilen = klen + sublen;
				v += sublen + 1;
			}

			/* empty dummy value */
			sb_concat(sb, "*: \"\"");

			assert(m < 256);
			multi[m++] = key;
			multi[m++] = val;
			continue;
		} else {
			sb_concat(sb, ": ");
		}

		if (!valid_unquoted(val)) {
			/* +2 for quotes */
			int len = 2;
			char *buf, *r = val, *w, c;
			while ((c = *r++)) {
				len++;
				if (c == '\\' || c == '"')
					len++;
			}
			buf = w = malloc(len + 1);
			r = val;
			*w++ = '"';
			while ((c = *r++)) {
				if (c == '\\' || c == '"')
					*w++ = '\\';
				*w++ = c;
			}
			*w++ = '"';
			*w = '\0';
			sb_concat(sb, buf);
			free(buf);
		} else {
			sb_concat(sb, val);
		}
	}

	if (m > 0) {
		char temp[32];
		int tag;

		/* don't let him set his own _data-tag for multiline messages. */
		/* we COULD detect it, but i don't feel like doing that. */
		if (aa_has(args, "_data-tag")) {
			sb_free(sb);
			va_end(argp);
			aa_free(args);
			return 0;
		}

		do {
			tag = get_rand() & 0xFFFFFF;
		} while (tag == mcp->last_tag);
		mcp->last_tag = tag;

		snprintf(temp, sizeof(temp), " _data-tag: %06X", tag);
		sb_concat(sb, temp);
	}

	mcp->send(mcp->data, sb->str);
	sb_free(sb);

	/* did we have any multi-line values? */
	if (m > 0) {
		int len, mi = 0;
		char *buf;

		/* 5ch prefix, 6ch tag, 2 spaces and 1 colon */
		len = 5 + 6 + 3 + multilen;
		buf = malloc(len + 1);

		while (mi + 1 < m) {
			char *v, *vend;
			int sublen;
			key = multi[mi++];
			val = multi[mi++];
			v = val;
			vend = val + strlen(val);

			while (v < vend) {
				sublen = strcspn(v, "\n");
				snprintf(buf, len + 1, "#$#* %06X %s: %.*s", mcp->last_tag, key, sublen, v);
				mcp->send(mcp->data, buf);
				v = v + sublen + 1;
			}
		}

		snprintf(buf, len + 1, "#$#: %06X", mcp->last_tag);
		mcp->send(mcp->data, buf);
		free(buf);
	}

	va_end(argp);
	aa_free(args);
	return 1;
}

void mcp_sendraw(McpState *mcp, char *str)
{
	/* have to escape MCP... */
	if (!strncmp(str, "#$#", 3)) {
		int len = strlen(str) - 3;
		char *tmp = memcpy(malloc(len + 1), str + 3, len + 1);
		mcp->send(mcp->data, tmp);
		free(tmp);
	} else {
		mcp->send(mcp->data, str);
	}
}

int mcp_supports(McpState *mcp, char *msgname)
{
	return aa_has(mcp->handlers, msgname);
}

McpMessage* mcp_newmsg(char *name)
{
	McpMessage *msg = memset(malloc(sizeof(McpMessage)), 0, sizeof(McpMessage));
	msg->name = str_dup(name);
	msg->args = aa_new(&free);
	return msg;
}

void mcp_freemsg(McpMessage *msg)
{
	free(msg->name);
	aa_free(msg->args);
	free(msg);
}

void mcp_addarg(McpMessage *msg, char *key, char *val)
{
	if (valid_unquoted(val)) {
		aa_insert(msg->args, key, str_dup(val));
	} else {
		/* +2 for quotes */
		int len = 2;
		char *buf, *r = val, *w, c;
		while ((c = *r++)) {
			len++;
			if (c == '\\' || c == '"')
				len++;
		}
		buf = w = malloc(len + 1);
		r = val;
		*w++ = '"';
		while ((c = *r++)) {
			if (c == '\\' || c == '"')
				*w++ = '\\';
			*w++ = c;
		}
		*w++ = '"';
		*w = '\0';
		aa_insert(msg->args, key, buf);
	}
}

char* mcp_getarg(McpMessage *msg, char *key)
{
	return (char*)aa_get(msg->args, key);
}

McpPackage* mcp_newpkg(char *name, int minver, int maxver)
{
	McpPackage *pkg = memset(malloc(sizeof(McpPackage)), 0, sizeof(McpPackage));
	pkg->name = str_dup(name);
	pkg->minver = minver;
	pkg->maxver = maxver;
	pkg->funcs = aa_new(&free);
	return pkg;
}

void mcp_freepkg(McpPackage *pkg)
{
	free(pkg->name);
	aa_free(pkg->funcs);
	free(pkg);
}

int mcp_addfunc(McpPackage *pkg, char *name, McpFunc fn)
{
	return aa_insert(pkg->funcs, name, mcp_wrapfn(fn, NULL));
}

int mcp_register(McpState *mcp, McpPackage *pkg)
{
	McpPackageInfo *info = memset(malloc(sizeof(McpPackageInfo)), 0, sizeof(McpPackageInfo));
	info->version = 0;
	info->pkg = pkg;
	return aa_insert(mcp->pkgs, pkg->name, info);
}
