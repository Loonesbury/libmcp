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
	return !strpbrk(s, "\"*\\: \n");
}

typedef struct McpArg {
	int multi;
	union {
		char *str;
		strbuf *buf;
	} val;
} McpArg;

static McpArg* new_arg(char *s, int multi)
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

static void free_arg(void *val)
{
	McpArg *arg = (McpArg*)val;
	if (arg->multi)
		sb_free(arg->val.buf);
	else
		free(arg->val.str);
	free(arg);
}

static void arg_to_str(aa_node *n, void *unused)
{
	McpArg *arg = (McpArg*)n->val;
	if (arg->multi) {
		/* replace trailing '\n' with a terminator */
		/* XXX: we really should have a sb_ func for this */
		strbuf *sb = arg->val.buf;
		sb->str[sb->len - 1] = '\0';
		n->val = (void*)sb_release(arg->val.buf);
	} else {
		n->val = (void*)arg->val.str;
	}
	free(arg);
}

/* replaces McpArgs with their char* values */
static void convert_args(aa_tree *args)
{
	aa_foreach(args, &arg_to_str, NULL);
	args->freeval = &free;
}

int ver_check(int low, int high, int min, int max)
{
	if (high >= min && max >= low)
		return (high > max) ? max : high;
	return 0;
}

int ver_toint(char *s)
{
	char *n = s;
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

static void notify_pkg(aa_node *n, void *arg)
{
	char vstr[16];
	McpState *mcp = (McpState*)arg;
	McpPackage *pkg = ((McpPackageInfo*)n->val)->pkg;

	MCP_START("mcp-negotiate-can");
	MCP_ADD("min-version", ver_tostr(pkg->minver, vstr, sizeof(vstr)));
	MCP_ADD("max-version", ver_tostr(pkg->maxver, vstr, sizeof(vstr)));
	MCP_SEND();
}

/* this is a builtin because reasons */
static MCP_PROTO(mcpfn_mcp)
{
	/* our supported version */
	int min, max;
	/* their supported version */
	int from, to;

	/* already received 'mcp'? */
	if (mcp->version != 0)
		return MCP_ERROR;

	min  = max = MCP_VERSION(2, 1);
	from = ver_toint(MCP_GET("version"));
	to   = ver_toint(MCP_GET("to"));

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
		char *authkey = MCP_GET("authentication-key");
		if (!valid_unquoted(authkey)) {
			mcp->version = -1;
			return MCP_ERROR;
		}
		mcp->authkey = str_dup(authkey);
	} else {
		MCP_START("mcp");
		MCP_ADD("version", "2.1");
		MCP_ADD("to", "2.1");
		MCP_ADD("authentication-key", mcp->authkey);
		MCP_SEND();
	}

	/* both sides send packages */
	aa_foreach(mcp->pkgs, &notify_pkg, mcp);
	/* mcp-negotiate 1.0 doesn't recognize 'end', but it should be */
	/* safely ignored by a compliant implementation */
	MCP_START("mcp-negotiate-end");
	MCP_SEND();

	return MCP_OK;
}

McpFuncInfo* mcp_wrapfn(McpFunc fn, McpPackageInfo *pinfo)
{
	McpFuncInfo *func = memset(malloc(sizeof(McpFuncInfo)), 0, sizeof(McpFuncInfo));
	func->pinfo = pinfo;
	func->fn = fn;
	return func;
}

/* XXX: awful kludge to suppress warnings about incompatible pointer types */
static void aa_free_(void *t) {
	aa_free((aa_tree*)t);
}

static McpState* new_state(McpSendFunc sendfn, char *authkey, void *data)
{
	McpState *mcp = memset(malloc(sizeof(McpState)), 0, sizeof(McpState));
	if (authkey)
		mcp->authkey = str_dup(authkey);
	else
		mcp->data = data;

	mcp->funcs = aa_new(&free);
	mcp->pkgs = aa_new(&free);
	mcp->mlines = aa_new(&aa_free_);
	mcp->send = sendfn;

	aa_insert(mcp->funcs, "mcp", mcp_wrapfn(&mcpfn_mcp, NULL));

	return mcp;
}

McpState *mcp_newclient(McpSendFunc sendfn, char *authkey)
{
	if (!authkey || !valid_unquoted(authkey))
		return NULL;
	return new_state(sendfn, authkey, NULL);
}

McpState* mcp_newserver(McpSendFunc sendfn, void *data)
{
	return new_state(sendfn, NULL, data);
}

void mcp_free(McpState *mcp)
{
	free(mcp->authkey);
	aa_free(mcp->pkgs);
	aa_free(mcp->funcs);
	aa_free(mcp->mlines);
	if (mcp->inargs)
		aa_free(mcp->inargs);
	if (mcp->outmsg)
		mcp_freemsg(mcp->outmsg);
	free(mcp);
}

static int handle_msg(McpState *mcp, char *name, aa_tree *args)
{
	McpMessage msg;
	McpFuncInfo *func;
	int rv;

	if (strcmp(name, "mcp") && mcp->version <= 0)
		return MCP_ERROR;

	func = (McpFuncInfo*)aa_get(mcp->funcs, name);
	assert(func != NULL);

	msg.name = name;
	msg.args = args;
	msg.pkg = func->pinfo;

	mcp->inargs = args;
	rv = func->fn(mcp, func->pinfo, &msg);
	mcp->inargs = NULL;

	return rv;
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

	/* continue multi-line value */
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

		convert_args(args);
		rv = handle_msg(mcp, name, args);
		aa_remove(mcp->mlines, authkey);
		return rv;
	}

	if (strcmp(name, "mcp")) {
		if (strcmp(authkey, mcp->authkey))
			return MCP_ERROR;
	}

	if (!aa_get(mcp->funcs, name))
		return MCP_ERROR;

	args = aa_new(&free_arg);

	/* parse arguments */
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

		/*
		* to make multi-lines easier to deal with, we store values as McpArgs
		* and replace them with chars* before calling the message func.
		*
		* we COULD keep track of 2 sets of keys, one char*s and one McpArgs,
		* but that would be a lot uglier.
		*/
		aa_insert(args, argk, new_arg(argv, multiarg));

		SKIP_WS(b);
	}

	if (multi) {
		McpArg *tag = (McpArg*)aa_get(args, "_data-tag");
		if (tag == NULL || tag->multi || !valid_unquoted(tag->val.str)) {
			aa_free(args);
			return MCP_ERROR;
		}

		aa_insert(args, "*name*", new_arg(name, 0));
		aa_insert(mcp->mlines, tag->val.str, args);
		return MCP_OK;
	}

	convert_args(args);
	rv = handle_msg(mcp, name, args);
	aa_free(args);
	return rv;
}

int mcp_start(McpState *mcp, char *name)
{
	/* started a new message without ending the previous one */
	assert(mcp->outmsg == NULL);
	if (!mcp_supports(mcp, name))
		return 0;
	mcp->outmsg = mcp_newmsg(name);
	return 1;
}

void mcp_addarg(McpState *mcp, char *key, char *val)
{
	assert(mcp->outmsg != NULL);
	assert(valid_ident(key));
	mcp_addmsg(mcp->outmsg, key, val);
}

void mcp_send(McpState *mcp)
{
	assert(mcp->outmsg != NULL);
	mcp_sendmsg(mcp, mcp->outmsg);
	mcp_freemsg(mcp->outmsg);
	mcp->outmsg = NULL;
}

int mcp_sendsimple(McpState *mcp, char *name, int nkeys, ...)
{
	va_list argp;
	char *key, *val;
	int i;

	if (!mcp_start(mcp, name))
		return 0;

	va_start(argp, nkeys);
	for (i = 0; i < nkeys; i++) {
		key = va_arg(argp, char*);
		assert(valid_ident(key));
		val = va_arg(argp, char*);
		mcp_addarg(mcp, key, val);
	}
	va_end(argp);

	mcp_send(mcp);
	return 1;
}

typedef struct bufinfo {
	McpState *mcp;
	char *buf, *s, *e;
	int err;
} bufinfo;

int cat_buf(bufinfo *b, char *fmt, ...)
{
	int szleft = b->e - b->s;
	int ct;
	va_list argp;

	assert(szleft > 0);
	if (b->err)
		return 0;

	va_start(argp, fmt);
	ct = vsnprintf(b->s, szleft, fmt, argp);
	va_end(argp);

	if (ct < 0 || ct >= szleft) {
		b->err = 1;
		return 0;
	}
	b->s += ct;
	return 1;
}

static void cat_arg(aa_node *n, void *arg)
{
	bufinfo *b = (bufinfo*)arg;
	if (!valid_ident(n->key))
		b->err = 2;
	if (b->err)
		return;

	if (strchr(n->val, '\n') != NULL) {
		/* add dummy value. */
		cat_buf(b, " %s*: \"\"", n->key);
	} else {
		cat_buf(b, " %s: %s", n->key, n->val);
	}
}

static void send_multiline(aa_node *n, void *arg)
{
	if (strchr(n->val, '\n')) {
		bufinfo *b = (bufinfo*)arg;
		McpState *mcp = b->mcp;
		char *v = n->val, *vend = (char*)n->val + strlen(n->val);
		int sublen;

		while (v < vend) {
			sublen = strcspn(v, "\n");
			snprintf(b->s, b->e - b->s, "%s: %.*s", n->key, sublen, v);
			mcp->send(mcp->data, b->buf);
			v = v + sublen + 1;
		}
	}
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

int mcp_sendmsg(McpState *mcp, McpMessage *msg)
{
	struct bufinfo b;
	int len, ok, ismcp = !strcmp(msg->name, "mcp");
	char tagstr[32];

	if (!mcp_supports(mcp, msg->name))
		return 0;

	len = 3 + strlen(msg->name) + msg->arglen;
	if (msg->multilen > 0) {
		int tag;
		do {
			tag = get_rand() & 0xFFFFFF;
		} while (tag == mcp->last_tag);
		mcp->last_tag = tag;
		snprintf(tagstr, sizeof(tagstr), "%06X", tag);
		/* if he was a goof and inserted his own _data-tag, we overwrite it */
		aa_insert(msg->args, "_data-tag", tagstr);
		len += 3 + 9 + 6;
	}

	if (!ismcp)
		len += 1 + strlen(mcp->authkey);

	b.s = b.buf = malloc(len + 1);
	b.e = b.s + len + 1;
	b.err = 0;

	if (ismcp) {
		ok = cat_buf(&b, "#$#mcp");
	} else {
		ok = cat_buf(&b, "#$#%s %s", msg->name, mcp->authkey);
	}
	assert(ok);
	aa_foreach(msg->args, &cat_arg, &b);
	if (b.err == 2) {
		free(b.buf);
		return 0;
	}
	assert(!b.err);
	assert(b.s + 1 == b.e);

	mcp->send(mcp->data, b.buf);
	free(b.buf);

	/* handle multi-line values */
	if (msg->multilen > 0) {
		/* 5ch prefix, 6ch tag, 2 spaces and 1 colon */
		len = 5 + 6 + 3 + msg->multilen;

		b.buf = b.s = malloc(len + 1);
		b.e = b.s + len + 1;
		b.mcp = mcp;

		ok = cat_buf(&b, "#$#* %6.6s ", tagstr);
		assert(ok);

		aa_foreach(msg->args, &send_multiline, &b);
		assert(!b.err);
		snprintf(b.buf, len + 1, "#$#: %6.6s", tagstr);
		mcp->send(mcp->data, b.buf);

		free(b.buf);
	}

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
	return aa_has(mcp->funcs, msgname);
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

int mcp_addmsg(McpMessage *msg, char *key, char *val)
{
	if (!valid_ident(key) || aa_has(msg->args, key))
		return 0;

	/* +3 for delimiters */
	msg->arglen += 3 + strlen(key);

	/* multi-line value */
	if (strchr(val, '\n') != NULL) {
		/* need to check each line to see if we'll need a wider buffer */
		char *v = val, *vend = val + strlen(val);
		int klen = strlen(key), sublen = -1;
		while (v < vend) {
			sublen = strcspn(v, "\n");
			if (klen + sublen > msg->multilen)
				msg->multilen = klen + sublen;
			v += sublen + 1;
		}

		/* value isn't sent as a key-val, so we don't need to escape it */
		aa_insert(msg->args, key, str_dup(val));

		/* +1 for asterisk, +2 for empty quotes */
		msg->arglen += 3;

	/* simple unquoted value */
	} else if (valid_unquoted(val)) {
		aa_insert(msg->args, key, str_dup(val));
		msg->arglen += strlen(val);

	/* quoted value */
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
		msg->arglen += len;
	}

	return 1;
}

char* mcp_getarg(McpState *mcp, char *key)
{
	assert(mcp->inargs != NULL);
	return (char*)aa_get(mcp->inargs, key);
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

McpPackageInfo* mcp_register(McpState *mcp, McpPackage *pkg)
{
	McpPackageInfo *info;
	if (aa_has(mcp->pkgs, pkg->name))
		return NULL;
	info = memset(malloc(sizeof(McpPackageInfo)), 0, sizeof(McpPackageInfo));
	info->version = 0;
	info->pkg = pkg;
	aa_insert(mcp->pkgs, pkg->name, info);
	return info;
}
