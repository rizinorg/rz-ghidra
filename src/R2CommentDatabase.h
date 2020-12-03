// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_R2COMMENTDATABASE_H
#define RZ_GHIDRA_R2COMMENTDATABASE_H

#include <comment.hh>

class R2Architecture;

class R2CommentDatabase : public CommentDatabase
{
		R2Architecture *arch;
		mutable CommentDatabaseInternal cache;
		mutable bool cache_filled;
		void fillCache(const Address &fad) const;

	public:
		R2CommentDatabase(R2Architecture *arch);

		void clear() override;
		void clearType(const Address &fad, uint4 tp) override;

		void addComment(uint4 tp, const Address &fad, const Address &ad, const string &txt) override;
		bool addCommentNoDuplicate(uint4 tp, const Address &fad, const Address &ad, const string &txt) override;

		void deleteComment(Comment *com) override { throw LowlevelError("deleteComment unimplemented"); }

		CommentSet::const_iterator beginComment(const Address &fad) const override;
		CommentSet::const_iterator endComment(const Address &fad) const override;

		void saveXml(ostream &s) const override { cache.saveXml(s); }
		void restoreXml(const Element *el, const AddrSpaceManager *trans) override { throw LowlevelError("commentdb::restoreXml unimplemented"); }
};

#endif //RZ_GHIDRA_R2COMMENTDATABASE_H
