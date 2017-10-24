#include <stdio.h>
#include <stdlib.h>
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
	char c = *s;
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
		strbuf *sb = sb_new();
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

static int ver_ge(short *a, short *b)
{
	return (a[0] > b[0]) || (a[0] == b[0] && a[1] >= b[1]);
}

short* mcp_checkversion(short *low, short *high, short *min, short *max)
{
	if (ver_ge(high, min) && ver_ge(max, low)) {
		if (ver_ge(high, max))
			return max;
		else
			return high;
	}
	return NULL;
}

int ver_fromstr(char *str, short *i)
{
	char *s = str, *dot = NULL;
	if (!str)
		return 0;

	if (!isdigit(*s++))
		return 0;
	while (*s) {
		if (*s == '.') {
			if (dot)
				return 0;
			dot = s;
		} else if (!isdigit(*s)) {
			return 0;
		}
		s++;
	}
	while (*s == ' ')
		s++;
	if (*s || !dot)
		return 0;
	*dot = '\0';
	i[0] = atoi(str);
	i[1] = atoi(dot + 1);
	*dot = '.';

	return 1;
}

void ver_tostr(short *i, char *str)
{
	sprintf(str, "%.7h.%.7h", i[0], i[1]);
}

/* hardcoded - we do not support 1.0 */
static short ourver[2] = {2, 1};

static void foreach_pkgs(aa_node *n, void *arg)
{
	char vstr[16];
	McpState *mcp = (McpState*)arg;
	McpPackage *pkg = (McpPackage*)n->val;

	McpMessage *msg = mcp_newmsg("mcp-negotiate-can");
	mcp_addarg(msg, "package", pkg->name);

	ver_tostr(pkg->minver, vstr);
	mcp_addarg(msg, "min-version", vstr);

	ver_tostr(pkg->maxver, vstr);
	mcp_addarg(msg, "max-version", vstr);

	mcp_send(mcp, msg);
	mcp_freemsg(msg);
}

/* this is a builtin because reasons */
static int mcpfn_mcp(McpState *mcp, McpMessage *msg)
{
	short minver[2], maxver[2];
	McpMessage *endmsg;

	/* already received 'mcp'? */
	if (mcp->status != MCP_STATUS_UNK)
		return MCP_ERROR;

	if (!ver_fromstr(mcp_getarg(msg, "version"), minver) ||
		!ver_fromstr(mcp_getarg(msg, "to"), minver) ||
		!mcp_checkversion(minver, maxver, ourver, ourver))
	{
		mcp->status = MCP_STATUS_NO;
		return MCP_ERROR;
	}

	if (mcp->server) {
		/* server gets authkey from client */
		char *authkey = mcp_getarg(msg, "authentication-key");
		if (!valid_unquoted(authkey)) {
			mcp->status = MCP_STATUS_NO;
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
	mcp->status = MCP_STATUS_YES;

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
	if (mcp->handlers)
		aa_free(mcp->handlers);
	if (mcp->mlines)
		aa_free(mcp->mlines);
}

static int handle_msg(McpState *mcp, char *name, aa_tree *args)
{
	static McpMessage msg;
	McpFuncHandle *h;

	msg.name = name;
	msg.args = args;
	msg.len = 0;

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

static void cat_args(aa_node *n, void *arg)
{
	char **s = (char**)arg;
	*s += sprintf(*s, " %s: %s", n->key, (char*)n->val);
}

void mcp_send(McpState *mcp, McpMessage *msg)
{
	char *buf, *b;
	msg->len += 1 + strlen(mcp->authkey);
	if (msg->args->size > 0)
		msg->len++;

	buf = b = malloc(msg->len + 1);
	b += sprintf(b, "#$#%s %s", msg->name, mcp->authkey);
	aa_foreach(msg->args, &cat_args, &b);

	mcp->send(mcp->data, buf);
	free(buf);
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

McpMessage* mcp_newmsg(char *name)
{
	int len = strlen(name);
	McpMessage *msg = memset(malloc(sizeof(McpMessage)), 0, sizeof(McpMessage));
	msg->name = memcpy(malloc(len + 1), name, len + 1);
	msg->len = 3 + len;
	msg->args = aa_new(&free);
	return msg;
}

void mcp_freemsg(McpMessage *msg)
{
	if (msg->args)
		aa_free(msg->args);
	free(msg);
}

void mcp_addarg(McpMessage *msg, char *key, char *val)
{
	if (valid_unquoted(val)) {
		aa_insert(msg->args, key, str_dup(val));
		msg->len += (3 + strlen(key) + strlen(val));
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
		/* +3 for delimiters and colon */
		msg->len += (3 + strlen(key) + len);
	}
}

char* mcp_getarg(McpMessage *msg, char *key)
{
	return (char*)aa_get(msg->args, key);
}

McpPackage* mcp_newpkg(char *name, short minmajor, short minminor, short maxmajor, short maxminor)
{
	McpPackage *pkg = memset(malloc(sizeof(McpPackage)), 0, sizeof(McpPackage));
	pkg->name = str_dup(name);

	pkg->minver[0] = minmajor;
	pkg->minver[1] = minminor;
	pkg->maxver[0] = maxmajor;
	pkg->maxver[1] = maxminor;

	pkg->funcs = aa_new(&free);
	return pkg;
}

void mcp_freepkg(McpPackage *pkg)
{
	if (pkg->name)
		free(pkg->name);
	if (pkg->funcs)
		aa_free(pkg->funcs);
	free(pkg);
}

int mcp_addfunc(McpPackage *pkg, char *name, McpFunc fn)
{
	McpFuncHandle *h = malloc(sizeof(McpFuncHandle));
	h->fn = fn;
	return aa_insert(pkg->funcs, name, h);
}

int mcp_register(McpState *mcp, McpPackage *pkg)
{
	return aa_insert(mcp->pkgs, pkg->name, pkg);
}
