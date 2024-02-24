// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinARCHITECTURE_H
#define RZ_GHIDRA_RizinARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"

#include "RzCoreMutex.h"

class RizinTypeFactory;
typedef struct rz_core_t RzCore;

class RizinArchitecture : public ghidra::SleighArchitecture
{
	private:
		RzCoreMutex coreMutex;

		RizinTypeFactory *rizinTypeFactory = nullptr;
		std::map<std::string, ghidra::VarnodeData> registers;
		std::vector<std::string> warnings;

		bool rawptr = false;

		void loadRegisters(const ghidra::Translate *translate);

	public:
		explicit RizinArchitecture(RzCore *core, const std::string &sleigh_id);

		RzCoreMutex *getCore() { return &coreMutex; }

		RizinTypeFactory *getTypeFactory() const { return rizinTypeFactory; }

		ghidra::ProtoModel *protoModelFromRizinCC(const char *cc);
		ghidra::Address registerAddressFromRizinReg(const char *regname);

		void addWarning(const std::string &warning)	{ warnings.push_back(warning); }
		const std::vector<std::string> getWarnings() const { return warnings; }
		ghidra::ContextDatabase *getContextDatabase();

		void setRawPtr(bool rawptr) { this->rawptr = rawptr; }

	protected:
		ghidra::Translate *buildTranslator(ghidra::DocumentStorage &store) override;
		void buildLoader(ghidra::DocumentStorage &store) override;
		ghidra::Scope *buildDatabase(ghidra::DocumentStorage &store) override;
		void buildTypegrp(ghidra::DocumentStorage &store) override;
		void buildCoreTypes(ghidra::DocumentStorage &store) override;
		void buildCommentDB(ghidra::DocumentStorage &store) override;
		void postSpecFile() override;
		void buildAction(ghidra::DocumentStorage &store) override;
};


#endif //RZ_GHIDRA_RizinARCHITECTURE_H
