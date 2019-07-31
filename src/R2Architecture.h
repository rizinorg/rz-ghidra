/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2ARCHITECTURE_H
#define R2GHIDRA_R2ARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"
#include "printcoffsets.hh"

#include <r_core.h>

class R2TypeFactory;

class R2Architecture : public SleighArchitecture
{
	private:
		RCore *core;
		R2TypeFactory *r2TypeFactory = nullptr;
		std::map<std::string, VarnodeData> registers;
		std::vector<std::string> warnings;

		void loadRegisters(const Translate *translate);

	public:
		explicit R2Architecture(RCore *core);

		RCore *getCore() const 	{ return core; }
		R2TypeFactory *getTypeFactory() const { return r2TypeFactory; }

		ProtoModel *protoModelFromR2CC(const char *cc);
		Address registerAddressFromR2Reg(const char *regname);

		void addWarning(const std::string &warning)	{ warnings.push_back(warning); }
		const std::vector<std::string> getWarnings() const { return warnings; }
		PrintLanguage *print_with_offsets;

	protected:
		Translate *buildTranslator(DocumentStorage &store) override;
		void buildLoader(DocumentStorage &store) override;
		Scope *buildGlobalScope() override;
		void buildTypegrp(DocumentStorage &store) override;
		void buildCommentDB(DocumentStorage &store) override;
};

#endif //R2GHIDRA_R2ARCHITECTURE_H
