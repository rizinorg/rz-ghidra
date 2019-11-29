/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2PrintC.h"

#include <varnode.hh>
#include <architecture.hh>

// Constructing this registers the capability
R2PrintCCapability R2PrintCCapability::inst;

R2PrintCCapability::R2PrintCCapability(void)
{
	name = "r2-c-language";
	isdefault = false;
}

PrintLanguage *R2PrintCCapability::buildLanguage(Architecture *glb)
{
	return new R2PrintC(glb, name);
}

R2PrintC::R2PrintC(Architecture *g, const string &nm)
	: PrintC(g, nm)
{
}

void R2PrintC::pushUnnamedLocation(const Address &addr, const Varnode *vn, const PcodeOp *op)
{
	// print (*(type *)0x0000...) instead of ram00000...
	AddrSpace *space = addr.getSpace();
	if(space->getType() == IPTR_PROCESSOR)
	{
		pushOp(&dereference, op);
		auto type = glb->types->getTypePointer(space->getAddrSize(), vn->getType(), space->getWordSize());
		pushConstant(addr.getOffset(), type, vn, op);
	}
	else
	{
		PrintC::pushUnnamedLocation(addr,vn, op);
	}
}