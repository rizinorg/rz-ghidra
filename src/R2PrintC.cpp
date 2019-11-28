/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2PrintC.h"

#include <varnode.hh>

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
	// print (*(type *)0x0000...) instead of uRam00000...
	if(addr.getSpace()->getType() == IPTR_PROCESSOR)
	{
		ostringstream s;
		s << "(*(" << vn->getType()->getName() << " *)";
		addr.printRaw(s);
		s << ")";
		pushAtom(Atom(s.str(), vartoken, EmitXml::var_color, op, vn));
	}
	else
	{
		PrintC::pushUnnamedLocation(addr,vn, op);
	}
}