#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "mcp.h"
#include "aa.h"

#ifdef _MSC_VER
#define strdup _strdup
#endif

extern char* lower_str(char *s);
#define valid_unquoted mcp_validkey
extern McpFuncInfo* mcp_wrapfn(McpFunc fn, McpPackageInfo *pinfo);

static int ver_check(int low, int high, int min, int max)
{
	if (high >= min && max >= low)
		return (high > max) ? max : high;
	return -1;
}

static int ver_toint(char *s)
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

static char* ver_tostr(int ver, char *str, int sz)
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
	if (mcp->version <= 0) {
		/* not technically an error */
		return MCP_OK;
	}

	if (mcp->server) {
		/* server gets authkey from client */
		char *authkey = MCP_GET("authentication-key");
		if (!valid_unquoted(authkey)) {
			mcp->version = -1;
			return MCP_ERROR;
		}
		mcp->authkey = strdup(authkey);
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
	/* MCP_START("mcp-negotiate-end");
	MCP_SEND(); */

	return MCP_OK;
}

typedef struct McpRegInfo {
	McpState *state;
	McpPackageInfo *pinfo;
} McpRegInfo;

static void register_func(aa_node *n, void *arg)
{
	McpRegInfo *reg = arg;
	McpState *mcp = reg->state;
	McpPackageInfo *pinfo = reg->pinfo;
	char *pkgname = pinfo->pkg->name;
	char *msgname = n->key;
	McpFunc fn = ((McpFuncInfo*)n->val)->fn;

	if (*msgname) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s-%s", pkgname, msgname);
		aa_insert(mcp->funcs, buf, mcp_wrapfn(fn, pinfo));
	} else {
		/* blank name - same as package */
		aa_insert(mcp->funcs, pkgname, mcp_wrapfn(fn, pinfo));
	}
}

static MCP_PROTO(mcpfn_negotiate_can)
{
	McpPackageInfo *pinfo;
	McpRegInfo reg;
	char *pkgname;
	int ourmin, ourmax, minver, maxver;

	pkgname = MCP_GET("package");
	if (!pkgname)
		return MCP_ERROR;
	lower_str(pkgname);

	pinfo = aa_get(mcp->pkgs, pkgname);
	if (!pinfo)
		return MCP_OK;

	ourmin = pinfo->pkg->minver;
	ourmax = pinfo->pkg->maxver;
	minver = ver_toint(MCP_GET("min-version"));
	maxver = ver_toint(MCP_GET("max-version"));

	if (minver < 0 || maxver < 0) {
		/* the standard doesn't say that 0.0 is an illegal version */
		/* so we only halt for malformed numbers */
		mcp->version = -1;
		return MCP_ERROR;
	}

	pinfo->version = ver_check(minver, maxver, ourmin, ourmax);
	if (!pinfo->version)
		return MCP_OK;

	reg.state = mcp;
	reg.pinfo = pinfo;
	aa_foreach(pinfo->pkg->funcs, &register_func, &reg);

	return MCP_OK;
}

static MCP_PROTO(mcpfn_negotiate_end)
{
	return MCP_OK;
}

void mcp_addbuiltins(McpState *mcp)
{
	McpPackage *pkg;
	McpRegInfo reg;
	McpPackageInfo *pinfo;

	aa_insert(mcp->funcs, "mcp", mcp_wrapfn(&mcpfn_mcp, NULL));

	pkg = mcp_newpkg("mcp-negotiate", MCP_VERSION(1, 0), MCP_VERSION(2, 0));
	mcp_addfunc(pkg, "can", &mcpfn_negotiate_can);
	mcp_addfunc(pkg, "end", &mcpfn_negotiate_end);

	/* as recommended by the spec, just use 2.0 anyway */
	pinfo = mcp_register(mcp, pkg);
	pinfo->version = MCP_VERSION(2, 0);
	/* make sure it's freed */
	pinfo->builtin = 1;

	reg.state = mcp;
	reg.pinfo = pinfo;
	aa_foreach(pkg->funcs, &register_func, &reg);
}
