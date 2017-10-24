#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "aa.h"

static aa_node* newnode(aa_tree *tree, char *key, void *val)
{
	aa_node *n = memset(malloc(sizeof(aa_node)), 0, sizeof(aa_node));

	if (key != NULL) {
		int keysz = strlen(key) + 1;
		n->key = memcpy(malloc(keysz), key, keysz);
	}
	n->val = val;
	n->left = n->right = tree->bottom;
	n->level = 1;

	tree->size++;
	return n;
}

static void freenode(aa_tree *tree, aa_node *n, int recurse)
{
	if (recurse) {
		if (n->left != tree->bottom)
			freenode(tree, n->left, 1);
		if (n->right != tree->bottom)
			freenode(tree, n->right, 1);
	} else {
		tree->size--;
	}

	free(n->key);
	if (n->val && tree->freeval)
		tree->freeval(n->val);
	free(n);
}

static aa_node* skew(aa_node *n)
{
	if (n->left->level == n->level) {
		/* rotate right */
		aa_node *temp = n;
		n = n->left;
		temp->left = n->right;
		n->right = temp;
	}
	return n;
}

static aa_node* split(aa_node *n)
{
	if (n->right->right->level == n->level) {
		/* rotate left */
		aa_node *temp = n;
		n = n->right;
		temp->right = n->left;
		n->left = temp;
		n->level++;
	}
	return n;
}

static aa_node* insertnode(aa_tree *tree, aa_node *n, char *key, void *val)
{
	int cmp;
	if (n == tree->bottom) {
		tree->ok = 1;
		return newnode(tree, key, val);
	}

	cmp = strcmp(key, n->key);
	if (cmp < 0) {
		n->left = insertnode(tree, n->left, key, val);
	} else if (cmp > 0) {
		n->right = insertnode(tree, n->right, key, val);
	} else {
		/* existing value is replaced */
		/* free(n->key);
		if (n->val && tree->freeval)
			tree->freeval(n->val);
		n->key = key;
		n->val = val; */
	}
	n = skew(n);
	n = split(n);
	return n;
}

static aa_node* removenode(aa_tree *tree, aa_node *n, char *key)
{
	int cmp;
	if (n == tree->bottom)
		return n;

	tree->last = n;

	/* 1: search down the tree and set pointers 'last' and 'deleted' */
	cmp = strcmp(key, n->key);
	if (cmp < 0) {
		n->left = removenode(tree, n->left, key);
	} else {
		tree->deleted = n;
		n->right = removenode(tree, n->right, key);
	}

	/* 2: at the bottom of the tree we remove the element IF it is present */
	if (n == tree->last && tree->deleted != tree->bottom && !cmp) {
		tree->ok = 1;
		free(tree->deleted->key);
		tree->deleted->key = tree->last->key;
		tree->deleted = tree->bottom;
		n = n->right;
		tree->last->key = NULL;
		freenode(tree, tree->last, 0);
	}
	/* 3: on the way back, we rebalance */
	else if (n->left->level < n->level - 1 || n->right->level < n->level - 1)
	{
		n->level -= 1;
		if (n->right->level > n->level)
			n->right->level = n->level;

		n = skew(n);
		n->right = skew(n->right);
		n->right->right = skew(n->right->right);
		n = split(n);
		n->right = split(n->right);
	}

	return n;
}

aa_tree* aa_new(aa_freefn freeval)
{
	aa_tree *tree = memset(malloc(sizeof(aa_tree)), 0, sizeof(aa_tree));
	tree->bottom = tree->top = tree->deleted = newnode(tree, NULL, NULL);
	tree->bottom->left = tree->bottom->right = tree->bottom;
	tree->bottom->level = 0;
	tree->freeval = freeval;
	return tree;
}

void aa_free(aa_tree* tree)
{
	if (tree->top != tree->bottom)
		freenode(tree, tree->top, 1);
	free(tree->bottom);
	free(tree);
}

int aa_insert(aa_tree *tree, char *key, void *val)
{
	assert(key != NULL);
	tree->ok = 0;
	tree->top = insertnode(tree, tree->top, key, val);
	return tree->ok;
}

int aa_remove(aa_tree *tree, char *key)
{
	assert(key != NULL);
	tree->ok = 0;
	tree->top = removenode(tree, tree->top, key);
	return tree->ok;
}

static aa_node* getnode(aa_tree *tree, char *key)
{
	aa_node *n = tree->top;
	int cmp;
	while (n != tree->bottom) {
		cmp = strcmp(key, n->key);
		if (!cmp)
			return n;
		n = (cmp < 0) ? n->left : n->right;
	}
	return n;
}

void* aa_get(aa_tree *tree, char *key)
{
	aa_node *n = getnode(tree, key);
	return (n) ? n->val : NULL;
}

int aa_has(aa_tree *tree, char *key)
{
	return getnode(tree, key) != NULL;
}

int aa_size(aa_tree *tree)
{
	return tree->size;
}

int aa_empty(aa_tree *tree)
{
	int sz = tree->size;
	if (tree->top)
		freenode(tree, tree->top, 1);
	tree->size = 0;
	return sz;
}

void foreachnode(aa_tree *tree, aa_node *n, aa_iterfn fn, void *arg)
{
	if (n->left != tree->bottom)
		foreachnode(tree, n->left, fn, arg);
	fn(n, arg);
	if (n->right != tree->bottom)
		foreachnode(tree, n->right, fn, arg);
}

void aa_foreach(aa_tree *tree, aa_iterfn fn, void *arg)
{
	if (tree->top == tree->bottom)
		return;
	foreachnode(tree, tree->top, fn, arg);
}

static void printnode(aa_tree *tree, aa_node *n, int i, int right)
{
	int j;
	if (n == tree->bottom)
		return;
	if (n->right != tree->bottom)
		printnode(tree, n->right, i + 1, 1);
	for (j = 0; j < i - 1; j++)
		printf("    ");
	if (i)
		printf(" %c==", right ? '/' : '\\');
	printf("%s\n", n->key);
	if (n->left != tree->bottom)
		printnode(tree, n->left, i + 1, 0);
}

void aa_print(aa_tree *tree)
{
	printnode(tree, tree->top, 0, 0);
}
