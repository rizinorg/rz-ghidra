/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2ARCHITECTURE_H
#define R2GHIDRA_R2ARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"

#include "RCoreMutex.h"

class R2TypeFactory;
typedef struct r_core_t RCore;

class R2Architecture : public SleighArchitecture
{
	private:
		RCoreMutex coreMutex;

		R2TypeFactory *r2TypeFactory = nullptr;
		std::map<std::string, VarnodeData> registers;
		std::vector<std::string> warnings;

		bool rawptr = false;

		void loadRegisters(const Translate *translate);

	public:
		explicit R2Architecture(RCore *core, const std::string &sleigh_id);

		RCoreMutex *getCore() { return &coreMutex; }

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


#endif //R2GHIDRA_R2ARCHITECTURE_H
