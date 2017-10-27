#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "mcp.h"
#include "aa.h"
#include "strbuf.h"

/* sets 'ret' to the current token and null-terminates it */
/* then skips whitespace afterward */
#define ADVANCE(ret, s)\
{\
	ret = s;\
	while (*s && *s != ' ') s++;\
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
		if (!isalnum(c) && c != '_')
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
		sb->str = s;
		sb->len = strlen(s);
		sb->size = sb->len + 1;
		arg->val.buf = sb;
	} else {
		arg->val.str = s;
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

static void foreach_args(aa_node *n, void *_)
{
	McpArg *arg = (McpArg*)n->val;
	if (arg->multi)
		n->val = (void*)sb_release(arg->val.buf);
	else
		n->val = (void*)arg->val.str;
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
	if (!n || n == s || *n != '.')
		return -1;
	ver += strtol((s = n + 1), &n, 10);
	if (!n || !*n)
		return ver;
	return -1;
}

void ver_tostr(int ver, char *str, int sz)
{
	snprintf(str, sz, "%i.%i", ver/1000, ver % 1000);
}

static void foreach_pkgs(aa_node *n, void *arg)
{
	char vstr[16];
	McpState *mcp = (McpState*)arg;
	McpPackage *pkg = (McpPackage*)n->val;

	McpMessage *msg = mcp_newmsg("mcp-negotiate-can");
	mcp_addarg(msg, "package", pkg->name);

	ver_tostr(pkg->minver, vstr, sizeof(vstr));
	mcp_addarg(msg, "min-version", vstr);

	ver_tostr(pkg->maxver, vstr, sizeof(vstr));
	mcp_addarg(msg, "max-version", vstr);

	mcp_send(mcp, msg);
	mcp_freemsg(msg);
}

/* this is a builtin because reasons */
static int mcpfn_mcp(McpState *mcp, McpMessage *msg)
{
	/* our supported version */
	int min = MCP_VERSION(2, 1), max = MCP_VERSION(2, 1);
	/* their supported version */
	int from, to;
	McpMessage *endmsg;

	/* already received 'mcp'? */
	if (mcp->version != 0)
		return MCP_ERROR;

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
		McpMessage *resp = mcp_newmsg("mcp");
		mcp_addarg(resp, "version", "2.1");
		mcp_addarg(resp, "to", "2.1");
		mcp_addarg(resp, "authentication-key", mcp->authkey);
		mcp_send(mcp, resp);
		mcp_freemsg(resp);
	}

	/* both sides send packages */
	aa_foreach(mcp->pkgs, &foreach_pkgs, mcp);

	/* mcp-negotiate 1.0 doesn't recognize 'end', but it should be */
	/* safely ignored by a compliant implementation */
	endmsg = mcp_newmsg("mcp-negotiate-end");
	mcp_send(mcp, endmsg);
	mcp_freemsg(endmsg);

	return MCP_OK;
}

static McpFuncHandle* mcp_wrapfn(McpFunc fn)
{
	McpFuncHandle *h = malloc(sizeof(McpFuncHandle));
	h->fn = fn;
	return h;
}

/* XXX: awful kludges to suppress warnings about incompatible pointer types */
static void aa_free_(void *t) {
	aa_free((aa_tree*)t);
}
static void mcp_freepkg_(void *pkg) {
	mcp_freepkg((McpPackage*)pkg);
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

	mcp->pkgs = aa_new(&mcp_freepkg_);

	aa_insert(mcp->handlers, "mcp", mcp_wrapfn(&mcpfn_mcp));

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
	McpFuncHandle *h;

	if (strcmp(name, "mcp") && mcp->version <= 0)
		return MCP_ERROR;

	msg.name = name;
	msg.args = args;

	h = (McpFuncHandle*)aa_get(mcp->handlers, name);
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
		if (!valid_unquoted(authkey)) {
			free(buf);
			return MCP_ERROR;
		}
	}

	/* continue a multi-line argument */
	if (!strcmp(name, "*")) {
		McpArg *arg;

		argk = b;
		args = (aa_tree*)aa_get(mcp->mlines, authkey);
		if (!args)
			return MCP_ERROR;

		/* wow! this is terrible! */
		while (1) {
			char c = *b;
			if (c == ':')
				break;
			*b++ = tolower(c);
		}
		*b++ = '\0';

		if (!valid_ident(argk) || *b != ' ') {
			/* bad identifier, or no delimiter afterward */
			aa_remove(mcp->mlines, authkey);
			free(buf);
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

		name = ((strbuf*)aa_get(args, "*name*"))->str;
		assert(name != NULL);

		/* ARGH ARGH ARGH */
		aa_foreach(args, &foreach_args, NULL);
		args->freeval = &free;

		rv = handle_msg(mcp, name, args);
		aa_remove(mcp->mlines, authkey);

		free(buf);
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

		if (multiarg) {
			if (!strcmp(argk, "_data-tag")) {
				/* a wise guy, huh? */
				aa_free(args);
				return MCP_ERROR;
			}
			multi = 1;
		}
		aa_insert(args, argk, mcp_newarg(str_dup(argv), multiarg));

		SKIP_WS(b);
	}

	if (multi) {
		/* got a multi-line key around here somewhere. */
		McpArg *tag = (McpArg*)aa_get(args, "_data-tag");
		if (tag == NULL || !valid_unquoted(tag->val.str)) {
			/* or not. */
			aa_free(args);
			return MCP_ERROR;
		}
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

int mcp_send(McpState *mcp, McpMessage *msg)
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
	return aa_insert(pkg->funcs, name, mcp_wrapfn(fn));
}

int mcp_register(McpState *mcp, McpPackage *pkg)
{
	return aa_insert(mcp->pkgs, pkg->name, pkg);
}
