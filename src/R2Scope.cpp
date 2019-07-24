/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2Scope.h"
#include "R2Architecture.h"
#include "R2TypeFactory.h"
#include "R2Utils.h"

#include <funcdata.hh>

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

static std::string hex(ut64 v)
{
	std::stringstream ss;
	ss << "0x" << std::hex << v;
	return ss.str();
}

static Element *child(Element *el, const std::string &name, const std::map<std::string, std::string> &attrs = {})
{
	auto child = new Element(el);
	child->setName(name);
	el->addChild(child);
	for(const auto &attr : attrs)
		child->addAttribute(attr.first, attr.second);
	return child;
}

static Element *childAddr(Element *el, const std::string &name, const Address &addr)
{
	return child(el, name, {
		{ "space", addr.getSpace()->getName() },
		{ "offset", hex(addr.getOffset()) }
	});
}

static Element *childType(Element *el, Datatype *type)
{
	auto pointer = dynamic_cast<TypePointer *>(type);
	if(pointer)
	{
		Element *r = child(el, "type", {
				{ "name", "" },
				{ "size", to_string(pointer->getSize()) },
				{ "metatype", "ptr" }
		});
		childType(r, pointer->getPtrTo());
		return r;
	}

	auto array = dynamic_cast<TypeArray *>(type);
	if(array)
	{
		Element *r = child(el, "type", {
				{ "name", "" },
				{ "size", to_string(array->getSize()) },
				{ "arraysize", to_string(array->numElements()) },
				{ "metatype", "array" }
		});
		childType(r, array->getBase());
		return nullptr;
	}

	return child(el, "typeref", {
			{ "name", type->getName() },
			{ "id", hex(type->getId()) }
	});
}

static std::string to_string(const char *str)
{
	return std::string(str ? str : "(null)");
}

FunctionSymbol *R2Scope::registerFunction(RAnalFunction *fcn) const
{
	RCore *core = arch->getCore();

	// We use xml here, because the public interface for Functions
	// doesn't let us set up the scope parenting as we need it :-(

	Document doc;
	doc.setName("mapsym");

	auto functionElement = child(&doc, "function", {
			{ "name", fcn->name },
			{ "size", "1" }
	});

	childAddr(functionElement, "addr", Address(arch->getDefaultSpace(), fcn->addr));

	auto localDbElement = child(functionElement, "localdb", {
			{ "lock", "false" },
			{ "main", "stack" }
	});

	auto scopeElement = child(localDbElement, "scope", {
			{ "name", fcn->name }
	});

	child(child(scopeElement, "parent"), "val");
	child(scopeElement, "rangelist");

	auto symbollistElement = child(scopeElement, "symbollist");

	ProtoModel *proto = fcn->cc ? arch->protoModelFromR2CC(fcn->cc) : nullptr;
	if(!proto)
		arch->addWarning("Failed to match radare2 calling convention " + to_string(fcn->cc) + " to Decompiler ProtoModel");

	int4 extraPop = proto ? proto->getExtraPop() : arch->translate->getDefaultSize();
	if(extraPop == ProtoModel::extrapop_unknown)
		extraPop = arch->translate->getDefaultSize();

	RangeList varRanges; // to check for overlaps
	RList *vars = r_anal_var_all_list(core->anal, fcn);
	auto stackSpace = arch->getStackSpace();

	auto addrForVar = [&](RAnalVar *var) {
		switch(var->kind)
		{
			case R_ANAL_VAR_KIND_BPV:
			{
				uintb off;
				int delta = var->delta - extraPop; // not 100% sure if extraPop is correct here
				if(delta >= 0)
					off = delta;
				else
					off = stackSpace->getHighest() + delta + 1;
				return Address(stackSpace, off);
			}
			case R_ANAL_VAR_KIND_REG:
			{
				RRegItem *reg = r_reg_index_get(core->anal->reg, var->delta);
				if(!reg)
				{
					arch->addWarning("Register for arg " + to_string(var->name) + " not found");
					return Address();
				}

				auto ret = arch->registerAddressFromR2Reg(reg->name);
				if(ret.isInvalid())
					arch->addWarning("Failed to match register " + to_string(var->name) + " for arg " + to_string(var->name));

				return ret;
			}
			default:
				return Address();
		}
	};

	ParamActive params(false);

	if(vars)
	{
		r_list_foreach_cpp<RAnalVar>(vars, [&](RAnalVar *var) {
			if(!var->isarg)
				return;
			auto addr = addrForVar(var);
			if(addr.isInvalid())
			{
				arch->addWarning("Failed to get address for var " + to_string(var->name));
				return;
			}
			params.registerTrial(addr, var->size);
			int4 i = params.whichTrial(addr, var->size);
			params.getTrial(i).markActive();
		});
	}

	if(proto)
		proto->deriveInputMap(&params);

	if(vars)
	{
		r_list_foreach_cpp<RAnalVar>(vars, [&](RAnalVar *var) {
			Datatype *type = var->type ? arch->getTypeFactory()->fromCString(var->type) : nullptr;
			bool typelock = true;
			if(!type)
			{
				arch->addWarning("Failed to match type " + to_string(var->type) + " for variable " + to_string(var->name) + " to Decompiler type");
				typelock = false;
				type = arch->types->findByName("uint32_t");
			}

			auto addr = addrForVar(var);
			if(addr.isInvalid())
			{
				if(var->isarg) // Already emitted this warning before
					arch->addWarning("Failed to get address for var " + to_string(var->name));
				return;
			}

			uintb last = addr.getOffset();
			if(type->getSize() > 0)
				last += type->getSize() - 1;
			bool overlap = false;
			if(typelock)
			{
				for(const auto &range : varRanges)
				{
					if(range.getSpace() != addr.getSpace())
						continue;
					if(range.getFirst() > last)
						continue;
					if(range.getLast() < addr.getOffset())
						continue;
					overlap = true;
					break;
				}
			}

			if(overlap)
			{
				arch->addWarning("Detected overlap for variable " + to_string(var->name));

				if(var->isarg) // Can't have args with typelock=false, otherwise we get segfaults in the Decompiler
					return;

				typelock = false;
			}

			varRanges.insertRange(addr.getSpace(), addr.getOffset(), last);

			auto mapsymElement = child(symbollistElement, "mapsym");
			auto symbolElement = child(mapsymElement, "symbol", {
					{ "name", var->name },
					{ "typelock", typelock ? "true" : "false" },
					{ "namelock", "true" },
					{ "readonly", "false" },
					{ "cat", var->isarg ? "0" : "-1" }
			});

			if(var->isarg)
			{
				int4 paramIndex = params.whichTrial(addr, var->size);

				if(paramIndex < 0)
					arch->addWarning("Failed to determine arg index of " + to_string(var->name));

				symbolElement->addAttribute("index", to_string(paramIndex < 0 ? 0 : paramIndex));
			}

			childType(symbolElement, type);
			childAddr(mapsymElement, "addr", addr);

			auto rangelist = child(mapsymElement, "rangelist");
			if(var->isarg && var->kind == R_ANAL_VAR_KIND_REG)
			{
				// For reg args, add a range just before the function
				// This prevents the arg to be assigned as a local variable in the decompiled function,
				// which can make the code confusing to read.
				// (Ghidra does the same)
				Address rangeAddr(arch->getDefaultSpace(), fcn->addr > 0 ? fcn->addr - 1 : 0);
				child(rangelist, "range", {
						{ "space", rangeAddr.getSpace()->getName() },
						{ "first", hex(rangeAddr.getOffset()) },
						{ "last", hex(rangeAddr.getOffset()) }
				});
			}
		});
	}

	r_list_free(vars);

	auto prototypeElement = child(functionElement, "prototype", {
			{ "extrapop", to_string(extraPop) },
			{ "model", proto ? proto->getName() : "unknown" }
	});

	Address returnAddr(arch->getSpaceByName("register"), 0);
	bool returnFound = false;
	if(proto)
	{
		for(auto it=proto->effectBegin(); it!=proto->effectEnd(); it++)
		{
			if(it->getType() == EffectRecord::return_address)
			{
				returnAddr = it->getAddress();
				returnFound = true;
				break;
			}
		}
	}

	if(!returnFound)
		arch->addWarning("Failed to find return address in ProtoModel");

	auto returnsymElement = child(prototypeElement, "returnsym");
	childAddr(returnsymElement, "addr", returnAddr);

	child(returnsymElement, "typeref", {
			{ "name", "undefined" }
	});

	child(&doc, "addr", {
			{ "space", "ram" },
			{ "offset", hex(fcn->addr) }
	});

	child(&doc, "rangelist");

	auto sym = cache->addMapSym(&doc);
	return dynamic_cast<FunctionSymbol *>(sym);
}

Symbol *R2Scope::registerFlag(RFlagItem *flag) const
{
	uint4 attr = Varnode::namelock | Varnode::typelock;
	Datatype *type = nullptr;
	if(flag->space && !strcmp(flag->space->name, R_FLAGS_FS_STRINGS))
	{
		Datatype *ptype = arch->types->findByName("char");
		type = arch->types->getTypeArray(static_cast<int4>(flag->size), ptype);
		attr |= Varnode::readonly;
	}

	// TODO: more types

	if(!type)
	{
		type = arch->types->getTypeCode();
	}

	SymbolEntry *entry = cache->addSymbol(flag->name, type, Address(arch->getDefaultSpace(), flag->offset), Address());
	if(!entry)
		return nullptr;

	auto symbol = entry->getSymbol();
	cache->setAttribute(symbol, attr);

	return symbol;
}

Symbol *R2Scope::queryR2Absoulte(ut64 addr) const
{
	// TODO: sync
	RCore *core = arch->getCore();
	RAnalFunction *fcn = r_anal_get_fcn_at(core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	if(fcn)
		return registerFunction(fcn);

	// TODO: register more things

	RFlagItem *flag = r_flag_get_at(core->flags, addr, false);
	if(flag)
		return registerFlag(flag);

	return nullptr;
}


Symbol *R2Scope::queryR2(const Address &addr) const
{
	switch(addr.getSpace()->getType())
	{
		case IPTR_CONSTANT:
			break;
		case IPTR_PROCESSOR:
			return queryR2Absoulte(addr.getOffset());
		case IPTR_SPACEBASE:
			break;
		case IPTR_INTERNAL:
			break;
		case IPTR_FSPEC:
			break;
		case IPTR_IOP:
			break;
		case IPTR_JOIN:
			break;
	}
	return nullptr;
}

LabSymbol *R2Scope::queryR2FunctionLabel(const Address &addr) const
{
	// TODO: sync
	RCore *core = arch->getCore();

	RAnalFunction *fcn = r_anal_get_fcn_in(core->anal, addr.getOffset(), R_ANAL_FCN_TYPE_NULL);
	if(!fcn)
		return nullptr;

	const char *label = r_anal_fcn_label_at(core->anal, fcn, addr.getOffset());
	if(!label)
		return nullptr;

	return cache->addCodeLabel(addr, label);
}

SymbolEntry *R2Scope::findAddr(const Address &addr, const Address &usepoint) const
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

SymbolEntry *R2Scope::findContainer(const Address &addr, int4 size, const Address &usepoint) const
{
	SymbolEntry *entry = cache->findClosestFit(addr, size, usepoint);

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