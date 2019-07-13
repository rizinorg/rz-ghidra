/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2Scope.h"
#include "R2Architecture.h"

#include <r_anal.h>

R2Scope::R2Scope(R2Architecture *arch)
		: Scope("", arch),
		  arch(arch),
		  cache(new ScopeInternal("radare2-internal", arch))
{
}

R2Scope::~R2Scope()
{
	delete cache;
}

FunctionSymbol *R2Scope::registerFunction(RAnalFunction *fcn) const
{
	return cache->addFunction(Address(arch->getDefaultSpace(), fcn->addr), fcn->name);
}

Symbol *R2Scope::queryR2(const Address &addr) const
{
	// TODO: sync
	RCore *core = arch->getCore();
	RAnalFunction *fcn = r_anal_get_fcn_at(core->anal, addr.getOffset(), R_ANAL_FCN_TYPE_NULL);
	if(fcn)
		return registerFunction(fcn);

	// TODO: register more things

	return nullptr;
}

LabSymbol *R2Scope::queryR2FunctionLabel(const Address &addr) const
{
	// TODO
	return nullptr;
}

SymbolEntry *R2Scope::findAddr(const Address &addr,const Address &usepoint) const
{
	SymbolEntry *entry = cache->findAddr(addr,usepoint);
	if(entry)
		return entry->getAddr() == addr ? entry : nullptr;

	entry = cache->findContainer(addr, 1, Address());
	if(entry) // Address is already queried, but symbol doesn't start at our address
		return nullptr;

	Symbol *sym = queryR2(addr);
	entry = sym ? sym->getMapEntry(addr) : nullptr;

	return (entry && entry->getAddr() == addr) ? entry : nullptr;
}

SymbolEntry *R2Scope::findContainer(const Address &addr,int4 size, const Address &usepoint) const
{
	SymbolEntry *entry = cache->findClosestFit(addr,size,usepoint);

	if(!entry)
	{
		Symbol *sym = queryR2(addr);
		entry = sym ? sym->getMapEntry(addr) : nullptr;
	}

	if(entry)
	{
		// Entry contains addr, does it contain addr+size
		uintb last = entry->getAddr().getOffset() + entry->getSize() - 1;
		if (last < addr.getOffset() + size - 1)
			return nullptr;
	}

	return entry;
}

Funcdata *R2Scope::findFunction(const Address &addr) const
{
	Funcdata *fd = cache->findFunction(addr);
	if(fd)
		return fd;

	// Check if this address has already been queried,
	// (returning a symbol other than a function_symbol)
	if(cache->findContainer(addr, 1, Address()))
		return nullptr;

	FunctionSymbol *sym;
	sym = dynamic_cast<FunctionSymbol *>(queryR2(addr));
	if(sym)
		return sym->getFunction();

	return nullptr;
}

ExternRefSymbol *R2Scope::findExternalRef(const Address &addr) const
{
	ExternRefSymbol *sym = cache->findExternalRef(addr);
	if(sym)
		return sym;

	// Check if this address has already been queried,
	// (returning a symbol other than an external ref symbol)
	if(cache->findContainer(addr, 1, Address()))
		return nullptr;

	return dynamic_cast<ExternRefSymbol *>(queryR2(addr));
}

LabSymbol *R2Scope::findCodeLabel(const Address &addr) const
{
	LabSymbol *sym = cache->findCodeLabel(addr);
	if(sym)
		return sym;

	// Check if this address has already been queried,
	// (returning a symbol other than a code label)
	SymbolEntry *entry = cache->findAddr(addr,Address());
	if(entry)
		return nullptr;

	return queryR2FunctionLabel(addr);
}

Funcdata *R2Scope::resolveExternalRefFunction(ExternRefSymbol *sym) const
{
	return queryFunction(sym->getRefAddr());
}