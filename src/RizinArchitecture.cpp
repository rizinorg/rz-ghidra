// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinLoadImage.h"
#include "RizinScope.h"
#include "RizinArchitecture.h"
#include "RizinTypeFactory.h"
#include "RizinCommentDatabase.h"
#include "RizinUtils.h"
#include "ArchMap.h"

#include <funcdata.hh>
#include <coreaction.hh>

#include <iostream>
#include <cassert>

using namespace ghidra;

// maps rizin calling conventions to decompiler proto models
static const std::map<std::string, std::string> cc_map = {
		{ "cdecl", "__cdecl" },
		{ "fastcall", "__fastcall" },
		{ "ms", "__fastcall" },
		{ "stdcall", "__stdcall" },
		{ "cdecl-thiscall-ms", "__thiscall" },
		{ "sh32", "__stdcall" },
		{ "amd64", "__stdcall" },
		{ "arm64", "__cdecl" },
		{ "arm32", "__stdcall" },
		{ "arm16", "__stdcall" } /* not actually __stdcall */
};

std::string FilenameFromCore(RzCore *core)
{
	if(core && core->bin && core->bin->file)
		return core->bin->file;
	return std::string();
}

RizinArchitecture::RizinArchitecture(RzCore *core, const std::string &sleigh_id)
	: SleighArchitecture(FilenameFromCore(core), sleigh_id.empty() ? SleighIdFromCore(core) : sleigh_id, &std::cout),
	coreMutex(core)
{
}

ProtoModel *RizinArchitecture::protoModelFromRizinCC(const char *cc)
{
	auto it = cc_map.find(cc);
	if(it == cc_map.end())
		return nullptr;

	auto protoIt = protoModels.find(it->second);
	if(protoIt == protoModels.end())
		return nullptr;

	return protoIt->second;
}

static std::string lowercase(std::string str)
{
	std::transform(str.begin(), str.end(), str.begin(), [](int c){
		if(c >= 'A' && c <= 'Z') {
			return c - ('A' - 'a');
		}
		return c;
	});
	return str;
}

void RizinArchitecture::loadRegisters(const Translate *translate)
{
	registers = {};
	if(!translate)
		return;
	std::map<VarnodeData, std::string> regs;
	translate->getAllRegisters(regs);
	for(const auto &reg : regs)
	{
		registers[reg.second] = reg.first;
		auto lower = lowercase(reg.second);

		// as a fallback we also map all registers as lowercase
		if(registers.find(lower) == registers.end())
			registers[lower] = reg.first;
	}
}

Address RizinArchitecture::registerAddressFromRizinReg(const char *regname)
{
	loadRegisters(translate);
	auto it = registers.find(regname);
	if(it == registers.end())
		it = registers.find(lowercase(regname));
	if(it == registers.end())
		return Address(); // not found, invalid addr
	return it->second.getAddr();
}

Translate *RizinArchitecture::buildTranslator(DocumentStorage &store)
{
	Translate *ret = SleighArchitecture::buildTranslator(store);
	loadRegisters(ret);
	return ret;
}

ContextDatabase *RizinArchitecture::getContextDatabase()
{
	return context;
}

void RizinArchitecture::postSpecFile()
{
	RzCoreLock core(getCore());
	rz_list_foreach_cpp<RzAnalysisFunction>(core->analysis->fcns, [&](RzAnalysisFunction *func) {
		if (func->is_noreturn)
		{
			// Configure noreturn functions
			Funcdata *infd = symboltab->getGlobalScope()->queryFunction(Address(getDefaultCodeSpace(), func->addr));
			if(!infd)
				return;
			infd->getFuncProto().setNoReturn(true);
		}
	});
}

void RizinArchitecture::buildAction(DocumentStorage &store)
{
	parseExtraRules(store);	// Look for any additional rules
	allacts.universalAction(this);
	allacts.resetDefaults();
	if(rawptr)
	{
		allacts.cloneGroup("decompile", "decompile-deuglified");
		allacts.removeFromGroup("decompile-deuglified", "fixateglobals"); // this action (ActionMapGlobals) will create these ugly uRam0x12345s
		allacts.setCurrent("decompile-deuglified");
	}
}

void RizinArchitecture::buildLoader(DocumentStorage &store)
{
	RzCoreLock core(getCore());
	collectSpecFiles(*errorstream);
	loader = new RizinLoadImage(getCore(), this);
}

Scope *RizinArchitecture::buildDatabase(DocumentStorage &store)
{
	symboltab = new Database(this, false);
	Scope *globalscope = new RizinScope(this);
	symboltab->attachScope(globalscope, nullptr);
	return globalscope;
}

void RizinArchitecture::buildTypegrp(DocumentStorage &store)
{
	types = rizinTypeFactory = new RizinTypeFactory(this);
}

void RizinArchitecture::buildCoreTypes(DocumentStorage &store)
{
	// TODO: load from rizin?
	types->setCoreType("void", 1, TYPE_VOID, false);
	types->setCoreType("bool", 1, TYPE_BOOL, false);
	types->setCoreType("uint8_t", 1, TYPE_UINT, false);
	types->setCoreType("uint16_t", 2, TYPE_UINT, false);
	types->setCoreType("uint32_t", 4, TYPE_UINT, false);
	types->setCoreType("uint64_t", 8, TYPE_UINT, false);
	types->setCoreType("char", 1, TYPE_INT, true);
	types->setCoreType("int8_t", 1, TYPE_INT, false);
	types->setCoreType("int16_t", 2, TYPE_INT, false);
	types->setCoreType("int32_t", 4, TYPE_INT, false);
	types->setCoreType("int64_t", 8, TYPE_INT, false);
	types->setCoreType("float", 4, TYPE_FLOAT, false);
	types->setCoreType("double", 8, TYPE_FLOAT, false);
	types->setCoreType("float16", 16 ,TYPE_FLOAT, false);
	types->setCoreType("undefined", 1, TYPE_UNKNOWN, false);
	types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
	types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
	types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);
	types->setCoreType("code", 1, TYPE_CODE, false);
	types->setCoreType("char", 1, TYPE_INT, true);
	types->setCoreType("char16_t", 2, TYPE_INT, true);
	types->setCoreType("char32_t", 4, TYPE_INT, true);
	types->cacheCoreTypes();
}

void RizinArchitecture::buildCommentDB(DocumentStorage &store)
{
	commentdb = new RizinCommentDatabase(this);
}
