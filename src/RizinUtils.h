// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RIZINUTILS_H
#define RZ_GHIDRA_RIZINUTILS_H

#include <rz_vector.h>

typedef struct rz_list_t RzList;
typedef struct rz_list_iter_t RzListIter;

template<typename T, typename F> void rz_list_foreach_cpp(RzList *list, const F &func)
{
	for(RzListIter *it = list->head; it; it = it->n)
	{
		func(reinterpret_cast<T *>(it->data));
	}
}

template<typename T, typename F> void rz_interval_tree_foreach_cpp(RzIntervalTree *tree, const F &func)
{
	RzIntervalTreeIter it;
	for(it = rz_rbtree_first (&(tree)->root->node); rz_rbtree_iter_has(&it); rz_rbtree_iter_next (&(it)))
	{
		RzIntervalNode *node = rz_interval_tree_iter_get (&it);
		func(node, reinterpret_cast<T *>(node->data));
	}
}

template<typename T, typename F> void rz_vector_foreach_cpp(RzVector *vec, const F &func)
{
	void *it;
	rz_vector_foreach(vec, it)
	{
		func(reinterpret_cast<T *>(it));
	}
}

#endif //RZ_GHIDRA_RIZINUTILS_H
