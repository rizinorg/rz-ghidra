/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2CommentDatabase.h"
#include "R2Architecture.h"

#include <r_core.h>

#include "R2Utils.h"

R2CommentDatabase::R2CommentDatabase(R2Architecture *arch)
	: arch(arch),
	cache_filled(false)
{
}

void R2CommentDatabase::fillCache(const Address &fad) const
{
	RCoreLock core(arch->getCore());

	RAnalFunction *fcn = r_anal_get_function_at(core->anal, fad.getOffset());
	if(!fcn)
	{
		RList *fcns = r_anal_get_functions_in(core->anal, fad.getOffset());
		if(!r_list_empty(fcns))
			fcn = reinterpret_cast<RAnalFunction *>(r_list_first(fcns));
		r_list_free(fcns);
	}
	if(!fcn)
		return;

	r_interval_tree_foreach_cpp<RAnalMetaItem>(&core->anal->meta, [fad, fcn, this](RIntervalNode *node, RAnalMetaItem *meta) {
		if(!meta || meta->type != R_META_TYPE_COMMENT || !meta->str)
			return;
		if(!r_anal_function_contains(fcn, node->start))
			return;
		cache.addComment(Comment::user2, fad, Address(arch->getDefaultCodeSpace(), node->start), meta->str);
	});

	cache_filled = true;
}

void R2CommentDatabase::clear()
{
	cache.clear();
	cache_filled = false;
}

void R2CommentDatabase::clearType(const Address &fad, uint4 tp)
{
	cache.clearType(fad, tp);
}

void R2CommentDatabase::addComment(uint4 tp, const Address &fad, const Address &ad, const string &txt)
{
	cache.addComment(tp, fad, ad, txt);
}

bool R2CommentDatabase::addCommentNoDuplicate(uint4 tp, const Address &fad, const Address &ad, const string &txt)
{
	return cache.addCommentNoDuplicate(tp, fad, ad, txt);
}

CommentSet::const_iterator R2CommentDatabase::beginComment(const Address &fad) const
{
	fillCache(fad);
	return cache.beginComment(fad);
}

CommentSet::const_iterator R2CommentDatabase::endComment(const Address &fad) const
{
	return cache.endComment(fad);
}