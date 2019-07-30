/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2LoadImage.h"
#include "R2Scope.h"
#include "R2Architecture.h"
#include "R2TypeFactory.h"
#include "R2CommentDatabase.h"
#include "R2PrintC.h"
#include "R2Utils.h"
#include <funcdata.hh>

#include <iostream>

// maps radare2 asm/anal plugins names to sleigh language
static const std::map<std::string, std::string> arch_map = {
		{ "x8632", "x86" },
		{ "x8664", "x86" },
		{ "arm32", "ARM"},
		{ "arm64", "AARCH64" } ,
		{ "mips32", "MIPS" },
		{ "mips64", "MIPS" },
		{ "avr8", "avr8" } ,
		{ "avr32", "avr32a" } ,
		{ "dalvik32", "Dalvik" } ,
		{ "650216", "6502" } ,
		{ "java32", "JVM" } ,
		{ "hppa32", "pa-risc" } ,
		{ "ppc32", "PowerPC" } ,
		{ "ppc64", "PowerPC" } ,
		{ "sparc32", "sparc" } ,
		{ "sparc64", "sparc" } ,
		{ "msp43016", "TI_MSP430" } ,
		{ "m68k32", "68000" } ,
};

static const std::map<std::string, std::string> compiler_map = {
		{ "elf", "gcc" },
		{ "pe", "windows" },
		{ "mach0", "macosx" }
};

// maps radare2 calling conventions to decompiler proto models
static const std::map<std::string, std::string> cc_map = {
		{ "cdecl", "__cdecl" },
		{ "fastcall", "__fastcall" },
		{ "stdcall", "__stdcall" },
		{ "cdecl-thiscall-ms", "__thiscall" },
		{ "amd64", "__stdcall" }
};

std::string FilenameFromCore(RCore *core)
{
	return core->bin->file;
}

std:: string CompilerFromCore(RCore *core)
{
	RBinInfo *info = r_bin_get_info(core->bin);
	auto comp_it = compiler_map.find(info->rclass);
	if(comp_it == compiler_map.end())
		throw LowlevelError("Could not match container" + std::string(info->rclass) + " to sleigh compiler.");
	return comp_it->second;
}

std::string SleighIdFromCore(RCore *core)
{
	const char *arch = r_config_get(core->config, "asm.arch");
	bool be = r_config_get_i(core->config, "cfg.bigendian") != 0;
	std::string bits = to_string(r_config_get_i(core->config, "asm.bits"));

	if (!strcmp(arch, "arm") && bits == 64)
		return std::string("AARCH64:LE:64:v8A:default");

	auto arch_it = arch_map.find(arch);
	
	if(arch_it == arch_map.end())
		throw LowlevelError("Could not match asm.arch " + std::string(arch) + " to sleigh arch.");

	if (!strcmp(arch_it->second.c_str(), "avr8"))
		bits = 16;
	if (!strcmp(arch_it->second.c_str(), "JVM"))
		be = true;
	return arch_it->second + ":" + (be ? "BE" : "LE") + ":" + to_string(bits) + ":default:" + CompilerFromCore(core);
}

R2Architecture::R2Architecture(RCore *core)
	: SleighArchitecture(FilenameFromCore(core), SleighIdFromCore(core), &cout),
	core(core)
{
	print_with_offsets = new R2PrintC(this, string("tagged-c-language"));
}

ProtoModel *R2Architecture::protoModelFromR2CC(const char *cc)
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

void R2Architecture::loadRegisters(const Translate *translate)
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

Address R2Architecture::registerAddressFromR2Reg(const char *regname)
{
	loadRegisters(translate);
	auto it = registers.find(regname);
	if(it == registers.end())
		it = registers.find(lowercase(regname));
	if(it == registers.end())
		return Address(); // not found, invalid addr
	return it->second.getAddr();
}

Translate *R2Architecture::buildTranslator(DocumentStorage &store)
{
	Translate *ret = SleighArchitecture::buildTranslator(store);
	loadRegisters(ret);
	return ret;
}

void R2Architecture::postSpecFile()
{
	r_list_foreach_cpp<RAnalFunction>(core->anal->fcns, [&](RAnalFunction *func) {
		if (func->is_noreturn)
		{
			// Configure noreturn functions
			Funcdata *infd = symboltab->getGlobalScope()->queryFunction(Address(getDefaultSpace(), func->addr));
			infd->getFuncProto().setNoReturn(true);
		}
	});
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

void R2Architecture::buildTypegrp(DocumentStorage &store)
{
	types = r2TypeFactory = new R2TypeFactory(this);

	// TODO: load from r2?
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
	types->setCoreType("wchar", 2, TYPE_INT, true);
	types->cacheCoreTypes();
}

void R2Architecture::buildCommentDB(DocumentStorage &store)
{
	commentdb = new R2CommentDatabase(this);
}
