/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2LoadImage.h"
#include "R2Scope.h"
#include "R2Architecture.h"

#include <iostream>

std::string FilenameFromCore(RCore *core)
{
	return core->bin->file;
}

std::string TArgFromCore(RCore *core)
{
	// TODO
	return "x86:LE:64:default";
}

R2Architecture::R2Architecture(RCore *core)
	: SleighArchitecture(FilenameFromCore(core), TArgFromCore(core), &cout),
	core(core)
{
}

void R2Architecture::buildLoader(DocumentStorage &store)
{
	collectSpecFiles(*errorstream);
	loader = new R2LoadImage(core);
}

Scope *R2Architecture::buildGlobalScope()
{
	Scope *globalscope = symboltab->getGlobalScope();
	if(globalscope)
		return globalscope;

	globalscope = new R2Scope(this);
	symboltab->attachScope(globalscope, nullptr);
	return globalscope;
}