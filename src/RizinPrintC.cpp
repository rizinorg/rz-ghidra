// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinPrintC.h"
#include "RizinArchitecture.h"

#include <varnode.hh>
#include <architecture.hh>

#include <rz_core.h>

#include "RizinUtils.h"

using namespace ghidra;

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
		pushConstant(addr.getOffset(), type, vartoken, vn, op);
	}
	else
	{
		PrintC::pushUnnamedLocation(addr,vn, op);
	}
}

std::string RizinPrintC::genericFunctionName(const ghidra::Address &addr)
{
	auto arch = dynamic_cast<RizinArchitecture *>(glb);
	if (arch) {
		RzCoreLock core(arch->getCore());
		const RzList *flags = rz_flag_get_list(core->flags, addr.getOffset());
		if(flags)
		{
			RzListIter *iter;
			void *pos;
			rz_list_foreach(flags, iter, pos)
			{
				auto flag = reinterpret_cast<RzFlagItem *>(pos);
				if(flag->space && flag->space->name && !strcmp(flag->space->name, RZ_FLAGS_FS_SECTIONS))
					continue;
				if(core->flags->realnames && flag->realname)
					return flag->realname;
				return flag->name;
			}
		}
	}
	return PrintC::genericFunctionName(addr);
}
