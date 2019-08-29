/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2ARCHITECTURE_H
#define R2GHIDRA_R2ARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"

#include <r_core.h>

class R2TypeFactory;

class R2Architecture : public SleighArchitecture
{
	friend class RCoreLock;

	private:
		/**
		 * > 0 => awake
		 * == 0 => sleeping
		 */
		int caffeine_level;
		void *bed;

		RCore *_core;
		R2TypeFactory *r2TypeFactory = nullptr;
		std::map<std::string, VarnodeData> registers;
		std::vector<std::string> warnings;

		void loadRegisters(const Translate *translate);

	public:
		explicit R2Architecture(RCore *core, const std::string &sleigh_id);

		void sleepEnd();
		void sleepBegin();

		R2TypeFactory *getTypeFactory() const { return r2TypeFactory; }

		ProtoModel *protoModelFromR2CC(const char *cc);
		Address registerAddressFromR2Reg(const char *regname);

		void addWarning(const std::string &warning)	{ warnings.push_back(warning); }
		const std::vector<std::string> getWarnings() const { return warnings; }
		PrintLanguage *print_with_offsets;
		ContextDatabase *getContextDatabase();

	protected:
		Translate *buildTranslator(DocumentStorage &store) override;
		void buildLoader(DocumentStorage &store) override;
		Scope *buildGlobalScope() override;
		void buildTypegrp(DocumentStorage &store) override;
		void buildCommentDB(DocumentStorage &store) override;
		void postSpecFile() override;
};

class RCoreLock
{
	private:
		R2Architecture * const arch;

	public:
		explicit RCoreLock(R2Architecture * arch) : arch(arch) { arch->sleepEnd(); }
		~RCoreLock()				{ arch->sleepBegin(); }
		operator RCore *() const	{ return arch->_core; }
		RCore *operator->() const	{ return arch->_core; }

};

#endif //R2GHIDRA_R2ARCHITECTURE_H
