// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinCOMMENTDATABASE_H
#define RZ_GHIDRA_RizinCOMMENTDATABASE_H

#include <comment.hh>

class RizinArchitecture;

class RizinCommentDatabase : public CommentDatabase
{
		RizinArchitecture *arch;
		mutable CommentDatabaseInternal cache;
		mutable bool cache_filled;
		void fillCache(const Address &fad) const;

	public:
		RizinCommentDatabase(RizinArchitecture *arch);

		void clear() override;
		void clearType(const Address &fad, uint4 tp) override;

		void addComment(uint4 tp, const Address &fad, const Address &ad, const string &txt) override;
		bool addCommentNoDuplicate(uint4 tp, const Address &fad, const Address &ad, const string &txt) override;

		void deleteComment(Comment *com) override { throw LowlevelError("deleteComment unimplemented"); }

		CommentSet::const_iterator beginComment(const Address &fad) const override;
		CommentSet::const_iterator endComment(const Address &fad) const override;

		void encode(Encoder &encoder) const override { cache.encode(encoder); }
		void decode(Decoder &decoder) override { throw LowlevelError("CommentDatabaseGhidra::decode unimplemented"); }
};

#endif //RZ_GHIDRA_RizinCOMMENTDATABASE_H
