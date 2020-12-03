// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_R2ARCHITECTURE_H
#define RZ_GHIDRA_R2ARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"

#include "RzCoreMutex.h"

class R2TypeFactory;
typedef struct rz_core_t RzCore;

class R2Architecture : public SleighArchitecture
{
	private:
		RzCoreMutex coreMutex;

		R2TypeFactory *r2TypeFactory = nullptr;
		std::map<std::string, VarnodeData> registers;
		std::vector<std::string> warnings;

		bool rawptr = false;

		void loadRegisters(const Translate *translate);

	public:
		explicit R2Architecture(RzCore *core, const std::string &sleigh_id);

		RzCoreMutex *getCore() { return &coreMutex; }

		R2TypeFactory *getTypeFactory() const { return r2TypeFactory; }

		ProtoModel *protoModelFromR2CC(const char *cc);
		Address registerAddressFromR2Reg(const char *regname);

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


#endif //RZ_GHIDRA_R2ARCHITECTURE_H
