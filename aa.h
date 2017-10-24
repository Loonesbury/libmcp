#ifndef LIBMCP_AA_H
#define LIBMCP_AA_H

/*
* Implementation of Arne Andersson's AA trees
* http://user.it.uu.se/~arnea/abs/simp.html
*/
typedef struct aa_node {
	struct aa_node *left;
	struct aa_node *right;
	int level;
	char *key;
	void *val;
} aa_node;

typedef struct aa_tree {
	struct aa_node *top;
	struct aa_node *bottom;

	struct aa_node *last;
	struct aa_node *deleted;
	int size;
	int ok;

	int freekeys;
	void (*freeval)(void*);
} aa_tree;

typedef void (*aa_freefn)(void *val);
typedef void (*aa_iterfn)(aa_node *n, void *arg);

aa_tree* aa_new    (aa_freefn freeval);
void     aa_free   (aa_tree *tree);
int      aa_insert (aa_tree *tree, char *key, void *val);
int      aa_remove (aa_tree *tree, char *key);
int      aa_has    (aa_tree *tree, char *key);
void*    aa_get    (aa_tree *tree, char *key);
int      aa_size   (aa_tree *tree);
int      aa_empty  (aa_tree *tree);
void     aa_foreach(aa_tree *tree, aa_iterfn fn, void *arg);
void     aa_print  (aa_tree *tree);

#endif