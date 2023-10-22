// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinCommentDatabase.h"
#include "RizinArchitecture.h"

#include <rz_core.h>

#include "RizinUtils.h"

using namespace ghidra;

RizinCommentDatabase::RizinCommentDatabase(RizinArchitecture *arch)
	: arch(arch),
	cache_filled(false)
{
}

void RizinCommentDatabase::fillCache(const Address &fad) const
{
	RzCoreLock core(arch->getCore());

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, fad.getOffset());
	if(!fcn)
	{
		RzList *fcns = rz_analysis_get_functions_in(core->analysis, fad.getOffset());
		if(!rz_list_empty(fcns))
			fcn = reinterpret_cast<RzAnalysisFunction *>(rz_list_first(fcns));
		rz_list_free(fcns);
	}
	if(!fcn)
		return;

	rz_interval_tree_foreach_cpp<RzAnalysisMetaItem>(&core->analysis->meta, [fad, fcn, this](RzIntervalNode *node, RzAnalysisMetaItem *meta) {
		if(!meta || meta->type != RZ_META_TYPE_COMMENT || !meta->str)
			return;
		if(!rz_analysis_function_contains(fcn, node->start))
			return;
		cache.addComment(Comment::user2, fad, Address(arch->getDefaultCodeSpace(), node->start), meta->str);
	});

	cache_filled = true;
}

void RizinCommentDatabase::clear()
{
	cache.clear();
	cache_filled = false;
}

void RizinCommentDatabase::clearType(const Address &fad, uint4 tp)
{
	cache.clearType(fad, tp);
}

void RizinCommentDatabase::addComment(uint4 tp, const Address &fad, const Address &ad, const string &txt)
{
	cache.addComment(tp, fad, ad, txt);
}

bool RizinCommentDatabase::addCommentNoDuplicate(uint4 tp, const Address &fad, const Address &ad, const string &txt)
{
	return cache.addCommentNoDuplicate(tp, fad, ad, txt);
}

CommentSet::const_iterator RizinCommentDatabase::beginComment(const Address &fad) const
{
	fillCache(fad);
	return cache.beginComment(fad);
}

CommentSet::const_iterator RizinCommentDatabase::endComment(const Address &fad) const
{
	return cache.endComment(fad);
}
