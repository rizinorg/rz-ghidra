// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinPrintC.h"

#include <varnode.hh>
#include <architecture.hh>

// Constructing this registers the capability
RizinPrintCCapability RizinPrintCCapability::inst;

RizinPrintCCapability::RizinPrintCCapability(void)
{
	name = "rizin-c-language";
	isdefault = false;
}

PrintLanguage *RizinPrintCCapability::buildLanguage(Architecture *glb)
{
	return new RizinPrintC(glb, name);
}

RizinPrintC::RizinPrintC(Architecture *g, const string &nm)
	: PrintC(g, nm)
{
}

void RizinPrintC::pushUnnamedLocation(const Address &addr, const Varnode *vn, const PcodeOp *op)
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
