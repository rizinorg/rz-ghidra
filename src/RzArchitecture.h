// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RZARCHITECTURE_H
#define RZ_GHIDRA_RZARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"

#include "RzCoreMutex.h"

class RzTypeFactory;
typedef struct rz_core_t RzCore;

class RzArchitecture : public SleighArchitecture
{
	private:
		RzCoreMutex coreMutex;

		RzTypeFactory *rzTypeFactory = nullptr;
		std::map<std::string, VarnodeData> registers;
		std::vector<std::string> warnings;

		bool rawptr = false;

		void loadRegisters(const Translate *translate);

	public:
		explicit RzArchitecture(RzCore *core, const std::string &sleigh_id);

		RzCoreMutex *getCore() { return &coreMutex; }

		RzTypeFactory *getTypeFactory() const { return rzTypeFactory; }

		ProtoModel *protoModelFromRzCC(const char *cc);
		Address registerAddressFromRzReg(const char *regname);

		void addWarning(const std::string &warning)	{ warnings.push_back(warning); }
		const std::vector<std::string> getWarnings() const { return warnings; }
		ContextDatabase *getContextDatabase();

		void setRawPtr(bool rawptr) { this->rawptr = rawptr; }

	protected:
		Translate *buildTranslator(DocumentStorage &store) override;
		void buildLoader(DocumentStorage &store) override;
		Scope *buildGlobalScope() override;
		void buildTypegrp(DocumentStorage &store) override;
		void buildCommentDB(DocumentStorage &store) override;
		void postSpecFile() override;
		void buildAction(DocumentStorage &store) override;
};


#endif //RZ_GHIDRA_RZARCHITECTURE_H
