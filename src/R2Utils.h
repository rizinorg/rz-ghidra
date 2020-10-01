/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef RZ_GHIDRA_R2UTILS_H
#define RZ_GHIDRA_R2UTILS_H

typedef struct rz_list_t RzList;
typedef struct rz_list_iter_t RzListIter;

template<typename T, typename F> void rz_list_foreach_cpp(RzList *list, const F &func)
{
	for(RzListIter *it = list->head; it; it = it->n)
	{
		func(reinterpret_cast<T *>(it->data));
	}
}

template<typename T, typename F> void rz_interval_tree_foreach_cpp(RIntervalTree *tree, const F &func)
{
	RIntervalTreeIter it;
	for(it = rz_rbtree_first (&(tree)->root->node); rz_rbtree_iter_has(&it); rz_rbtree_iter_next (&(it)))
	{
		RIntervalNode *node = rz_interval_tree_iter_get (&it);
		func(node, reinterpret_cast<T *>(node->data));
	}
}

#endif //RZ_GHIDRA_R2UTILS_H
