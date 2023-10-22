// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinCOMMENTDATABASE_H
#define RZ_GHIDRA_RizinCOMMENTDATABASE_H

#include <comment.hh>

class RizinArchitecture;

class RizinCommentDatabase : public ghidra::CommentDatabase
{
		RizinArchitecture *arch;
		mutable ghidra::CommentDatabaseInternal cache;
		mutable bool cache_filled;
		void fillCache(const ghidra::Address &fad) const;

	public:
		RizinCommentDatabase(RizinArchitecture *arch);

		void clear() override;
		void clearType(const ghidra::Address &fad, ghidra::uint4 tp) override;

		void addComment(ghidra::uint4 tp, const ghidra::Address &fad, const ghidra::Address &ad, const std::string &txt) override;
		bool addCommentNoDuplicate(ghidra::uint4 tp, const ghidra::Address &fad, const ghidra::Address &ad, const std::string &txt) override;

		void deleteComment(ghidra::Comment *com) override { throw ghidra::LowlevelError("deleteComment unimplemented"); }

		ghidra::CommentSet::const_iterator beginComment(const ghidra::Address &fad) const override;
		ghidra::CommentSet::const_iterator endComment(const ghidra::Address &fad) const override;

		void encode(ghidra::Encoder &encoder) const override { cache.encode(encoder); }
		void decode(ghidra::Decoder &decoder) override { throw ghidra::LowlevelError("CommentDatabaseGhidra::decode unimplemented"); }
};

#endif //RZ_GHIDRA_RizinCOMMENTDATABASE_H
