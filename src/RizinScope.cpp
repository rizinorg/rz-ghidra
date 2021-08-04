// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinScope.h"
#include "RizinArchitecture.h"
#include "RizinTypeFactory.h"

#include <funcdata.hh>

#include <rz_version.h>
#include <rz_analysis.h>
#include <rz_core.h>

#include "RizinUtils.h"

RizinScope::RizinScope(RizinArchitecture *arch)
		: Scope(0, "", arch, this),
		  arch(arch),
		  cache(new ScopeInternal(0, "rizin-internal", arch, this)),
		  next_id(new uint8)
{
	*next_id = 1;
}

RizinScope::~RizinScope()
{
	delete cache;
}

Scope *RizinScope::buildSubScope(uint8 id, const string &nm)
{
	return new ScopeInternal(id, nm, arch);
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
				{ "name", type->getName() },
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

FunctionSymbol *RizinScope::registerFunction(RzAnalysisFunction *fcn) const
{
	RzCoreLock core(arch->getCore());

	const std::string rizinArch(rz_config_get(core->config, "asm.arch"));

	// We use xml here, because the public interface for Functions
	// doesn't let us set up the scope parenting as we need it :-(

	Document doc;
	doc.setName("mapsym");

	if (fcn->bits == 16 && !rizinArch.compare("arm")) {
		ContextDatabase * cdb = arch->getContextDatabase();
		cdb->setVariable("TMode", Address(arch->getDefaultCodeSpace(), fcn->addr), 1);
	}

	const char *fcn_name = fcn->name;
	if (core->flags->realnames) {
		const RzList *flags = rz_flag_get_list(core->flags, fcn->addr);
		if(flags)
		{
			RzListIter *iter;
			void *pos;
			rz_list_foreach(flags, iter, pos)
			{
				auto flag = reinterpret_cast<RzFlagItem *>(pos);
				if(flag->space && flag->space->name && !strcmp(flag->space->name, RZ_FLAGS_FS_SECTIONS))
					continue;
				if (flag->realname && *flag->realname) {
					fcn_name = flag->realname;
					break;
				}
			}
		}
	}

	auto functionElement = child(&doc, "function", {
			{ "name", fcn_name },
			{ "size", "1" },
			{ "id", hex(makeId()) }
	});

	childAddr(functionElement, "addr", Address(arch->getDefaultCodeSpace(), fcn->addr));

	auto localDbElement = child(functionElement, "localdb", {
			{ "lock", "false" },
			{ "main", "stack" }
	});

	auto scopeElement = child(localDbElement, "scope", {
			{ "name", fcn_name }
	});

	auto parentElement = child(scopeElement, "parent", {
			{"id", hex(uniqueId)}
	});
	child(parentElement, "val");
	child(scopeElement, "rangelist");

	auto symbollistElement = child(scopeElement, "symbollist");

	ProtoModel *proto = fcn->cc ? arch->protoModelFromRizinCC(fcn->cc) : nullptr;
	if(!proto)
	{
		if(fcn->cc)
			arch->addWarning("Matching calling convention " + to_string(fcn->cc) + " of function " + to_string(fcn_name) + " failed, args may be inaccurate.");
		else
			arch->addWarning("Function " + to_string(fcn_name) + " has no calling convention set, args may be inaccurate.");
	}

	int4 extraPop = proto ? proto->getExtraPop() : arch->translate->getDefaultSize();
	if(extraPop == ProtoModel::extrapop_unknown)
		extraPop = arch->translate->getDefaultSize();

	RangeList varRanges; // to check for overlaps
	RzList *vars = rz_analysis_var_all_list(core->analysis, fcn);
	auto stackSpace = arch->getStackSpace();

	auto addrForVar = [&](RzAnalysisVar *var, bool warn_on_fail) {
		switch(var->kind)
		{
			case RZ_ANALYSIS_VAR_KIND_BPV:
			{
				uintb off;
				int delta = var->delta + fcn->bp_off - extraPop; // not 100% sure if extraPop is correct here
				if(delta >= 0)
					off = delta;
				else
					off = stackSpace->getHighest() + delta + 1;
				return Address(stackSpace, off);
			}
			case RZ_ANALYSIS_VAR_KIND_REG:
			{
				RzRegItem *reg = rz_reg_index_get(core->analysis->reg, var->delta);
				if(!reg)
				{
					if(warn_on_fail)
						arch->addWarning("Register for arg " + to_string(var->name) + " not found");
					return Address();
				}

				auto ret = arch->registerAddressFromRizinReg(reg->name);
				if(ret.isInvalid() && warn_on_fail)
					arch->addWarning("Failed to match register " + to_string(var->name) + " for arg " + to_string(var->name));

				return ret;
			}
			case RZ_ANALYSIS_VAR_KIND_SPV:
				if(warn_on_fail)
					arch->addWarning("Var " + to_string(var->name) + " is stack pointer based, which is not supported for decompilation.");
				return Address();
			default:
				if(warn_on_fail)
					arch->addWarning("Failed to get address for var " + to_string(var->name));
				return Address();
		}
	};

	std::map<RzAnalysisVar *, Datatype *> var_types;

	ParamActive params(false);

	if(vars)
	{
		rz_list_foreach_cpp<RzAnalysisVar>(vars, [&](RzAnalysisVar *var) {
			std::string typeError;
			Datatype *type = var->type ? arch->getTypeFactory()->fromRzType(var->type, &typeError) : nullptr;
			if(!type)
			{
				char *tstr = rz_type_as_string(core->analysis->typedb, var->type);
				arch->addWarning("Failed to match type " + to_string(tstr ? tstr : "?") + " for variable " + to_string(var->name) + " to Decompiler type: " + typeError);
				rz_mem_free(tstr);
				type = arch->types->getBase(core->analysis->bits / 8, TYPE_UNKNOWN);
				if(!type)
					return;
			}
			if(type->getSize() < 1)
			{
				arch->addWarning("Type " + type->getName() + " of variable " + to_string(var->name) + " has size 0");
				return;
			}
			var_types[var] = type;

			if(!var->isarg)
				return;
			auto addr = addrForVar(var, true);
			if(addr.isInvalid())
				return;
			params.registerTrial(addr, type->getSize());
			int4 i = params.whichTrial(addr, type->getSize());
			params.getTrial(i).markActive();
		});
	}

	if(proto)
		proto->deriveInputMap(&params);

	auto childRegRange = [&](Element *e) {
		// For reg args, add a range just before the function
		// This prevents the arg to be assigned as a local variable in the decompiled function,
		// which can make the code confusing to read.
		// (Ghidra does the same)
		Address rangeAddr(arch->getDefaultCodeSpace(), fcn->addr > 0 ? fcn->addr - 1 : 0);
		child(e, "range", {
				{ "space", rangeAddr.getSpace()->getName() },
				{ "first", hex(rangeAddr.getOffset()) },
				{ "last", hex(rangeAddr.getOffset()) }
		});
	};

	if(vars)
	{
		std::vector<Element *> argsByIndex;

		rz_list_foreach_cpp<RzAnalysisVar>(vars, [&](RzAnalysisVar *var) {
			auto type_it = var_types.find(var);
			if(type_it == var_types.end())
				return;
			Datatype *type = type_it->second;
			bool typelock = true;

			auto addr = addrForVar(var, var->isarg /* Already emitted this warning before */);
			if(addr.isInvalid())
				return;

			uintb last = addr.getOffset();
			if(type->getSize() > 0)
				last += type->getSize() - 1;
			if(last < addr.getOffset())
			{
				arch->addWarning("Variable " + to_string(var->name) + " extends beyond the stackframe. Try changing its type to something smaller.");
				return;
			}
			bool overlap = false;
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

			if(overlap)
			{
				arch->addWarning("Detected overlap for variable " + to_string(var->name));

				if(var->isarg) // Can't have args with typelock=false, otherwise we get segfaults in the Decompiler
					return;

				typelock = false;
			}

			int4 paramIndex = -1;
			if(var->isarg)
			{
				if(proto && !proto->possibleInputParam(addr, type->getSize()))
				{
					// Prevent segfaults in the Decompiler
					arch->addWarning("Removing arg " + to_string(var->name) + " because it doesn't fit into ProtoModel");
					return;
				}

				paramIndex = params.whichTrial(addr, type->getSize());
				if(paramIndex < 0)
				{
					arch->addWarning("Failed to determine arg index of " + to_string(var->name));
					return;
				}
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
				if(argsByIndex.size() < paramIndex + 1)
					argsByIndex.resize(paramIndex + 1, nullptr);

				argsByIndex[paramIndex] = symbolElement;

				symbolElement->addAttribute("index", to_string(paramIndex < 0 ? 0 : paramIndex));
			}

			childType(symbolElement, type);
			childAddr(mapsymElement, "addr", addr);

			auto rangelist = child(mapsymElement, "rangelist");
			if(var->isarg && var->kind == RZ_ANALYSIS_VAR_KIND_REG)
				childRegRange(rangelist);
		});

		// Add placeholder args in gaps
		for(size_t i=0; i<argsByIndex.size(); i++)
		{
			if(argsByIndex[i])
				continue;

			auto trial = params.getTrial(i);

			Datatype *type = arch->types->getBase(trial.getSize(), TYPE_UNKNOWN);
			if(!type)
				continue;

			auto mapsymElement = child(symbollistElement, "mapsym");
			auto symbolElement = child(mapsymElement, "symbol", {
					{ "name", "placeholder_" + to_string(i) },
					{ "typelock", "true" },
					{ "namelock", "true" },
					{ "readonly", "false" },
					{ "cat", "0" },
					{ "index", to_string(i) }
			});

			childAddr(mapsymElement, "addr", trial.getAddress());
			childType(symbolElement, type);

			auto rangelist = child(mapsymElement, "rangelist");
			if(trial.getAddress().getSpace() != arch->translate->getStackSpace())
				childRegRange(rangelist);
		}
	}

	rz_list_free(vars);

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
		//if(!returnFound)
		//	arch->addWarning("Failed to find return address in ProtoModel");
	}
	// TODO: should we try to get the return address from rizin's cc?

	auto returnsymElement = child(prototypeElement, "returnsym");
	childAddr(returnsymElement, "addr", returnAddr);

	child(returnsymElement, "typeref", {
			{ "name", "undefined" }
	});

	child(&doc, "addr", {
			{ "space", arch->getDefaultCodeSpace()->getName() },
			{ "offset", hex(fcn->addr) }
	});

	child(&doc, "rangelist");

	auto sym = cache->addMapSym(&doc);
	return dynamic_cast<FunctionSymbol *>(sym);
}

Symbol *RizinScope::registerFlag(RzFlagItem *flag) const
{
	RzCoreLock core(arch->getCore());

	uint4 attr = Varnode::namelock | Varnode::typelock;
	Datatype *type = nullptr;
	if(flag->space && !strcmp(flag->space->name, RZ_FLAGS_FS_STRINGS))
	{
		RzBinString *str = nullptr;
		RzListIter *iter;
		void *pos;
		rz_list_foreach(core->bin->binfiles, iter, pos)
		{
			auto bf = reinterpret_cast<RzBinFile *>(pos);
			if(!bf->o)
				continue;
			void *s = ht_up_find(bf->o->strings_db, flag->offset, nullptr);
			if(s)
			{
				str = reinterpret_cast<RzBinString *>(s);
				break;
			}
		}
		Datatype *ptype;
		const char *tn = "char";
		if(str)
		{
			switch(str->type)
			{
				case RZ_STRING_TYPE_WIDE:
					tn = "char16_t";
					break;
				case RZ_STRING_TYPE_WIDE32:
					tn = "char32_t";
					break;
			}
		}
		ptype = arch->types->findByName(tn);
		int4 sz = static_cast<int4>(flag->size) / ptype->getSize();
		type = arch->types->getTypeArray(sz, ptype);
		attr |= Varnode::readonly;
	}

	// TODO: more types

	if(!type)
	{
		type = arch->types->getTypeCode();
	}

	// Check whether flags should be displayed by their real name
	const char *name = (core->flags->realnames && flag->realname) ? flag->realname : flag->name;
	SymbolEntry *entry = cache->addSymbol(name, type, Address(arch->getDefaultCodeSpace(), flag->offset), Address());
	if(!entry)
		return nullptr;

	auto symbol = entry->getSymbol();
	cache->setAttribute(symbol, attr);

	return symbol;
}

Symbol *RizinScope::queryRizinAbsolute(ut64 addr, bool contain) const
{
	RzCoreLock core(arch->getCore());

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr);
#if 0
	// This can cause functions to be registered twice (hello-arm test)
	if(!fcn && contain)
	{
		RzList *fcns = rz_analysis_get_functions_in(core->analysis, addr);
		if(!rz_list_empty(fcns))
			fcn = reinterpret_cast<RzAnalysisFunction *>(rz_list_first(fcns));
		rz_list_free(fcns);
	}
#endif
	if(fcn)
		return registerFunction(fcn);

	// TODO: register more things

	// TODO: correctly handle contain for flags
	const RzList *flags = rz_flag_get_list(core->flags, addr);
	if(flags)
	{
		RzListIter *iter;
		void *pos;
		rz_list_foreach(flags, iter, pos)
		{
			auto flag = reinterpret_cast<RzFlagItem *>(pos);
			if(flag->space && flag->space->name && !strcmp(flag->space->name, RZ_FLAGS_FS_SECTIONS))
				continue;
			return registerFlag(flag);
		}
	}
	return nullptr;
}


Symbol *RizinScope::queryRizin(const Address &addr, bool contain) const
{
	if(addr.getSpace() == arch->getDefaultCodeSpace() || addr.getSpace() == arch->getDefaultDataSpace())
		return queryRizinAbsolute(addr.getOffset(), contain);
	return nullptr;
}

LabSymbol *RizinScope::queryRizinFunctionLabel(const Address &addr) const
{
	RzCoreLock core(arch->getCore());

	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr.getOffset(), RZ_ANALYSIS_FCN_TYPE_NULL);
	if(!fcn)
		return nullptr;

	const char *label = rz_analysis_function_get_label_at(fcn, addr.getOffset());
	if(!label)
		return nullptr;

	return cache->addCodeLabel(addr, label);
}

SymbolEntry *RizinScope::findAddr(const Address &addr, const Address &usepoint) const
{
	SymbolEntry *entry = cache->findAddr(addr,usepoint);
	if(entry)
		return entry->getAddr() == addr ? entry : nullptr;

	entry = cache->findContainer(addr, 1, Address());
	if(entry) // Address is already queried, but symbol doesn't start at our address
		return nullptr;

	Symbol *sym = queryRizin(addr, false);
	entry = sym ? sym->getMapEntry(addr) : nullptr;

	return (entry && entry->getAddr() == addr) ? entry : nullptr;
}

SymbolEntry *RizinScope::findContainer(const Address &addr, int4 size, const Address &usepoint) const
{
	SymbolEntry *entry = cache->findClosestFit(addr, size, usepoint);

	if(!entry)
	{
		Symbol *sym = queryRizin(addr, true);
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

Funcdata *RizinScope::findFunction(const Address &addr) const
{
	Funcdata *fd = cache->findFunction(addr);
	if(fd)
		return fd;

	// Check if this address has already been queried,
	// (returning a symbol other than a function_symbol)
	if(cache->findContainer(addr, 1, Address()))
		return nullptr;

	FunctionSymbol *sym;
	sym = dynamic_cast<FunctionSymbol *>(queryRizin(addr, false));
	if(sym)
		return sym->getFunction();

	return nullptr;
}

ExternRefSymbol *RizinScope::findExternalRef(const Address &addr) const
{
	ExternRefSymbol *sym = cache->findExternalRef(addr);
	if(sym)
		return sym;

	// Check if this address has already been queried,
	// (returning a symbol other than an external ref symbol)
	if(cache->findContainer(addr, 1, Address()))
		return nullptr;

	return dynamic_cast<ExternRefSymbol *>(queryRizin(addr, false));
}

LabSymbol *RizinScope::findCodeLabel(const Address &addr) const
{
	LabSymbol *sym = cache->findCodeLabel(addr);
	if(sym)
		return sym;

	// Check if this address has already been queried,
	// (returning a symbol other than a code label)
	SymbolEntry *entry = cache->findAddr(addr, Address());
	if(entry)
		return nullptr;

	return queryRizinFunctionLabel(addr);
}

Funcdata *RizinScope::resolveExternalRefFunction(ExternRefSymbol *sym) const
{
	return queryFunction(sym->getRefAddr());
}
