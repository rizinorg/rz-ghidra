// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RzPrintC.h"

#include <varnode.hh>
#include <architecture.hh>

// Constructing this registers the capability
RzPrintCCapability RzPrintCCapability::inst;

RzPrintCCapability::RzPrintCCapability(void)
{
	name = "rizin-c-language";
	isdefault = false;
}

PrintLanguage *RzPrintCCapability::buildLanguage(Architecture *glb)
{
	return new RzPrintC(glb, name);
}

RzPrintC::RzPrintC(Architecture *g, const string &nm)
	: PrintC(g, nm)
{
}

void RzPrintC::pushUnnamedLocation(const Address &addr, const Varnode *vn, const PcodeOp *op)
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
