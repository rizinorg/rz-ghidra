/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2UTILS_H
#define R2GHIDRA_R2UTILS_H

typedef struct r_list_t RList;
typedef struct r_list_iter_t RListIter;

template<typename T, typename F> void r_list_foreach_cpp(RList *list, const F &func)
{
	for(RListIter *it = list->head; it; it = it->n)
	{
		func(reinterpret_cast<T *>(it->data));
	}
}

#endif //R2GHIDRA_R2UTILS_H
