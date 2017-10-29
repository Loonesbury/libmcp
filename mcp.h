#ifndef LIBMCP_H
#define LIBMCP_H
struct aa_tree;

/* MCP package - shared between multiple states */
typedef struct McpPackage {
	char *name;
	int minver;
	int maxver;
	struct aa_tree *funcs;
} McpPackage;

/* 'Loaded' package info, specific to each state */
typedef struct McpPackageInfo {
	McpPackage *pkg;
	/* version in use between client and server */
	int version;
} McpPackageInfo;

typedef struct McpMessage {
	char *name;
	struct aa_tree *args;
	McpPackageInfo *pkg;

	/* only used for outgoing messages */
	int arglen;   /* length of key-vals, including delimiters */
	int multilen; /* longest line of a multi-line value */
} McpMessage;

/*
* Callback to send raw output to the remote.
* If on server, 'data' is the pointer passed to mcp_newserver()
* If on client, 'data' is always NULL
*/
typedef void (*McpSendFunc)(void *data, char *str);

#define MCP_SENDARGS void *data, char *str
#define MCP_SENDPROTO(name) void name(MCP_SENDARGS)

/* Main MCP state */
typedef struct McpState {
	/*
	* version established between client and server
	* 0 if negotiation hasn't started
	* -1 if negotiation was malformed or versions were incompatible
	*/
	int version;
	/*
	* authkey for this session
	* (NULL on server until client sends 'mcp')
	*/
	char *authkey;

	int server; /* true if we are a server instance */
	void *data; /* 'data' pointer (NULL if client) */

	struct aa_tree *pkgs;  /* McpPackageInfo wrappers */
	struct aa_tree *funcs; /* McpFuncInfos for msgs the remote supports */

	int last_tag;           /* last _data-tag */
	struct aa_tree *mlines; /* unfinished multi-line args */

	struct aa_tree *inargs; /* for incoming messages */
	McpMessage *outmsg;     /* for outgoing messages */

	/* function pointer used for sending output */
	McpSendFunc send;
} McpState;

#define MCP_FUNCARGS McpState *mcp, McpPackageInfo *pkg, McpMessage *msg
#define MCP_PROTO(name) int name(MCP_FUNCARGS)

/* Callback for MCP messages */
typedef int (*McpFunc)(MCP_FUNCARGS);

/* Handle for funcs */
/* NOTE: Not shared between mcp->funcs and pkg->funcs */
typedef struct McpFuncInfo {
	McpPackageInfo *pinfo;
	McpFunc fn;
} McpFuncInfo;

#define MCP_NONE  0
#define MCP_OK    1
#define MCP_ERROR 2

#define MCP_VERSION(major,minor) ((major)*1000 + (minor))

/*
* Opens a new MCP state.
* - 'authkey' must be printable chars ONLY, except " * : \ <space>
* - 'data' is not freed by mcp_free()
*/
McpState* mcp_newclient(McpSendFunc fn, char *authkey);
McpState* mcp_newserver(McpSendFunc fn, void *data);
void      mcp_free(McpState *mcp);

/*
* Parses and handles any MCP in 'buf', which MAY BE MODIFIED.
* Input from the remote should all be routed through this function.
* Returns:
*   MCP_NONE   no mcp found, buf is a displayable line
*   MCP_OK     valid MCP,    buf should be discarded
*   MCP_ERROR  invalid MCP,  buf should be discarded
*/
int mcp_parse(McpState *mcp, char *buf);

/*
* Sends a NON-MCP line to the remote. Lines starting with "#$#" will be
* automatically escaped before sending. You don't HAVE to route all your
* output to the remote through here, but it helps.
*/
void mcp_sendraw(McpState *mcp, char *str);

/*
* Sends an MCP message to the remote. Returns false if message is unsupported.
* Values containing '\n' will be automatically sent as a multi-line message.
*
* THIS WILL PANIC ON INVALID INPUT:
* - Keys must follow C identifier rules, plus hyphens after first char
* - Values must be printable chars (32-126) plus newlines
*
* Ex:
*   if (mcp_begin(mcp, "mcp-cord-open")) {
*       mcp_arg(mcp, "_id", "I12345");
*       mcp_arg(mcp, "type", "whiteboard");
*       mcp_send(mcp);
*   }
*
*   mcp_sendsimple(mcp, "mcp-cord-open", 2,
*       "_id", "I12345",
*       "_type", "whiteboard"
*   )
*/
int   mcp_start (McpState *mcp, char *name);
void  mcp_addarg(McpState *mcp, char *key, char *val);
void  mcp_send  (McpState *mcp);
int   mcp_sendsimple(McpState *mcp, char *msgname, int nkeys, ...);

#define MCP_START(name) mcp_start(mcp, name)
#define MCP_ADD(key,val) mcp_addarg(mcp, key, val)
#define MCP_SEND() mcp_send(mcp)

McpMessage* mcp_newmsg (char *name);
int         mcp_addmsg (McpMessage *msg, char *key, char *val);
int         mcp_sendmsg(McpState *mcp, McpMessage *msg);
void        mcp_freemsg(McpMessage *msg);

int mcp_validkey(char *s);
int mcp_validinput(char *s);
int mcp_validident(char *s);

/* Returns true if the given message is supported */
int mcp_supports(McpState *mcp, char *msgname);

/*
* Creates a new MCP package. Packages must be registered before negotiation,
* and may be shared between multiple states; they are not freed by mcp_free().
*/
McpPackage* mcp_newpkg  (char *name, int minver, int maxver);
int         mcp_addfunc (McpPackage *pkg, char *name, McpFunc fn);
void        mcp_freepkg (McpPackage *pkg);

McpPackageInfo* mcp_register(McpState *mcp, McpPackage *pkg);

/* Gets an argument from inside an MCP func */
char* mcp_getarg(McpState *mcp, char *key);

#define MCP_GET(key) mcp_getarg(mcp, key)

#endif
