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
	/*
	* 0 if negotiation hasn't been started
	* -1 if bad negotiation or incompatible version
	*/
	int version;
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
} McpMessage;

/* Callback for MCP messages */
typedef int (*McpFunc)(McpState* mcp, McpMessage *msg);

typedef struct McpPackage {
	char *name;
	int minver;
	int maxver;
	struct aa_tree *funcs;
} McpPackage;

typedef struct McpFuncHandle {
	McpFunc fn;
} McpFuncHandle;

#define MCP_NONE  0
#define MCP_OK    1
#define MCP_ERROR 2

#define MCP_VERSION(major, minor) ((major)*1000 + (minor))

/*
* Opens a new MCP state.
* Client authkeys may NOT contain " * \ : <space>
*/
McpState* mcp_newclient(McpSendFunc fn, char *authkey);
McpState* mcp_newserver(McpSendFunc fn, void *data);
/*
* Frees an MCP state.
* Packages are NOT freed, nor is the data ptr passed to mcp_newserver().
*/
void mcp_free(McpState *mcp);

/* Returns true if the given message is supported */
int mcp_supports(McpState *mcp, char *msgname);

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
int mcp_send(McpState *mcp, McpMessage *msg);

/*
* sends a NON-MCP line to the remote. lines starting with "#$#" will be
* automatically escaped before sending. you don't HAVE to route all your
* output to the remote through here, but it's helpful.
*/
void mcp_sendraw(McpState *mcp, char *str);

McpMessage* mcp_newmsg (char *name);
void        mcp_freemsg(McpMessage *msg);
void        mcp_addarg (McpMessage *msg, char *key, char *val);
char*       mcp_getarg (McpMessage *msg, char *key);

McpPackage* mcp_newpkg (char *name, int minver, int maxver);
void        mcp_freepkg(McpPackage *pkg);
int         mcp_addfunc(McpPackage *pkg, char *name, McpFunc fn);

/*
* Registers a package for use. Must be done BEFORE negotiation.
* Packages may be registered with more than one MCP state, and
* are not freed when the state is freed.
*
* Returns true if the package was already registered.
*/
int mcp_register(McpState *mcp, McpPackage *pkg);

#endif
