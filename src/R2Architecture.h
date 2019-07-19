/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2ARCHITECTURE_H
#define R2GHIDRA_R2ARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"

#include <r_core.h>

class R2TypeFactory;

class R2Architecture : public SleighArchitecture
{
	private:
		RCore *core;
		R2TypeFactory *r2TypeFactory = nullptr;

	public:
		explicit R2Architecture(RCore *core);

		RCore *getCore() const 	{ return core; }
		R2TypeFactory *getTypeFactory() const { return r2TypeFactory; }

	protected:
		void buildLoader(DocumentStorage &store) override;
		Scope *buildGlobalScope() override;
		void buildTypegrp(DocumentStorage &store) override;
		void buildCommentDB(DocumentStorage &store) override;
};

#endif //R2GHIDRA_R2ARCHITECTURE_H
