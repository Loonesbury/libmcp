#ifndef LIBMCP_H
#define LIBMCP_H
struct aa_tree;

/*
* Callback to send raw output to the remote.
* If on server, 'data' is the pointer passed to mcp_newserver()
* If on client, 'data' is always NULL
*/
typedef void (*McpSendFunc)(void *data, char *str);

typedef struct McpState {
	int status;
	/* true if we are a server instance */
	int server;
	/* authkey for this session */
	char *authkey;
	/* server can store client data here */
	void *data;

	/* registered packages */
	struct aa_tree *pkgs;
	/* function pointers (for packages the remote supports ONLY!) */
	struct aa_tree *handlers;
	/* unfinished multi-line args */
	struct aa_tree *mlines;

	McpSendFunc send;
} McpState;

typedef struct McpMessage {
	char *name;
	struct aa_tree *args;
	int len;
} McpMessage;

/* Callback for MCP messages */
typedef int (*McpFunc)(McpState* mcp, McpMessage *msg);

typedef struct McpPackage {
	char *name;
	short version[2];
	short minver[2];
	short maxver[2];
	struct aa_tree *funcs;
} McpPackage;

typedef struct McpFuncHandle {
	McpFunc fn;
} McpFuncHandle;

#define MCP_STATUS_UNK 0 /* not negotiated yet */
#define MCP_STATUS_YES 1 /* negotiated, good to go */
#define MCP_STATUS_NO  2 /* version mismatch or invalid negotiation */

#define MCP_NONE  0
#define MCP_OK    1
#define MCP_ERROR 2

/*
* Opens a new MCP state.
* Client authkeys may NOT contain " * \ : <space>
*/
McpState* mcp_newclient(McpSendFunc fn, char *authkey);
McpState* mcp_newserver(McpSendFunc fn, void *data);
void      mcp_free     (McpState *mcp);

/*
* Parses and handles any MCP in 'buf', which MAY BE MODIFIED.
* Input from the remote should all be routed through this function.
*
* Returns:
*   MCP_NONE   no mcp found, buf is a displayable line
*   MCP_OK     valid MCP,    buf should be discarded
*   MCP_ERROR  invalid MCP,  buf should be discarded
*/
int mcp_parse(McpState *mcp, char *buf);

/*
* sends an MCP message to the remote; any arguments containing \n are
* automatically sent in multiline format.
*/
void mcp_send(McpState *mcp, McpMessage *msg);

/*
* sends a NON-MCP line to the remote. lines starting with "#$#" will be
* automatically escaped before sending. you don't HAVE to route all your
* output to the remote through here, but it's helpful.
*/
void mcp_sendraw(McpState *mcp, char *str);

McpMessage* mcp_newmsg(char *name);
void        mcp_freemsg(McpMessage *msg);
void        mcp_addarg(McpMessage *msg, char *key, char *val);
char*       mcp_getarg(McpMessage *msg, char *key);

McpPackage* mcp_newpkg (char *name, short minmajor, short minminor, short maxmajor, short maxminor);
void        mcp_freepkg(McpPackage *pkg);
int         mcp_addfunc(McpPackage *pkg, char *name, McpFunc fn);

int         mcp_register(McpState *mcp, McpPackage *pkg);

#endif
