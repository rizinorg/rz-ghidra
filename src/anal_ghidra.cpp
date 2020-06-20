/* radare - LGPL - Copyright 2020 - FXTi */

#include <r_lib.h>
#include <r_anal.h>
#include "SleighAsm.h"

static SleighAsm sanal;

static int archinfo(RAnal *anal, int query)
{
	if(!strcmp(anal->cpu, "x86"))
		return -1;

	sanal.init(anal);
	if(query == R_ANAL_ARCHINFO_ALIGN)
		return sanal.alignment;
	else
		return -1;
}

static int sleigh_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask)
{
}

static char *get_reg_profile(RAnal *anal)
{
	// TODO: parse call and return reg usage from compiler spec.
	// TODO: apply attribute get from processor spec(hidden, ...).
	if(!strcmp(anal->cpu, "x86"))
		return nullptr;

	/*
	 * By 2020-05-24, there are 17 kinds of group of registers in SLEIGH.
	 * I map them to r_reg.h's RRegisterType:
	 * R_REG_TYPE_XMM: 
	 * R_REG_TYPE_SEG: 
	 * R_REG_TYPE_DRX: DEBUG
	 * R_REG_TYPE_FPU: ST FPU
	 * R_REG_TYPE_MMX: MMX
	 * R_REG_TYPE_YMM: AVX
	 * R_REG_TYPE_FLG: FLAGS Flags
	 * R_REG_TYPE_GPR: PC Cx DCR STATUS SVE CONTROL SPR SPR_UNNAMED Alt NEON
	 */
	const char*   r_reg_type_arr[] = {"PC",  "Cx",  "DCR", "STATUS", "SVE", "CONTROL", "SPR", "SPR_UNNAMED", "Alt", "NEON", \
									"FLAGS", "Flags", \
									"AVX", \
									"MMX", \
									"ST", "FPU", \
									"DEBUG", \
									nullptr};
	const char* r_reg_string_arr[] = {"gpr", "gpr", "gpr", "gpr",    "gpr", "gpr",     "gpr", "gpr",         "gpr", "gpr",  \
									"flg",   "flg",   \
									"ymm", \
									"mmx", \
									"fpu", "fpu", \
									"drx", \
									nullptr};

	sanal.init(anal);

	auto reg_list = sanal.getRegs();
	std::stringstream buf;

	if(!sanal.pc_name.empty())
		buf << "=PC\t" << sanal.pc_name << '\n';
	if(!sanal.sp_name.empty())
		buf << "=SP\t" << sanal.pc_name << '\n';

	for(auto p = reg_list.begin(); p != reg_list.end(); p++)
	{
		const std::string &group = sanal.reg_group[p->name];
		if(group.empty())
		{
			buf << "gpr\t" << p->name << "\t." << p->size * 8 << "\t" << p->offset << "\t" << "0\n";
			continue;
		}

		for(size_t i = 0; ; i++)
		{
			if(!r_reg_type_arr[i])
			{
				fprintf(stderr, "anal_ghidra.cpp:get_reg_profile() -> Get unexpected Register group(%s) from SLEIGH, abort.", group.c_str());
				return nullptr;
			}

			if(group == r_reg_type_arr[i])
			{
				buf << r_reg_string_arr[i] << '\t';
				break;
			}
		}

		buf << p->name << "\t." << p->size * 8 << "\t" << p->offset << "\t" << "0\n";
	}
	const std::string &res = buf.str();
	fprintf(stderr, res.c_str());
	return strdup(res.c_str());
}

RAnalPlugin r_anal_plugin_ghidra = {
	/* .name = */ "r2ghidra",
	/* .desc = */ "SLEIGH Disassembler from Ghidra",
	/* .license = */ "GPL3",
	/* .arch = */ "sleigh",
	/* .author = */ "FXTi",
	/* .version = */ nullptr,
	/* .bits = */ 0,
	/* .esil = */ false, // can do esil or not
	/* .fileformat_type = */ 0,
	/* .init = */ nullptr,
	/* .fini = */ nullptr,
	/* .archinfo = */ &archinfo,
	/* .anal_mask = */ nullptr,
	/* .preludes = */ nullptr,
	/* .op = */ &sleigh_op,
	/* .cmd_ext = */ nullptr,
	/* .set_reg_profile = */ nullptr,
	/* .get_reg_profile = */ &get_reg_profile,
	/* .fingerprint_bb = */ nullptr,
	/* .fingerprint_fcn = */ nullptr,
	/* .diff_bb = */ nullptr,
	/* .diff_fcn = */ nullptr,
	/* .diff_eval = */ nullptr,
	/* .esil_init = */ nullptr,
	/* .esil_post_loop = */ nullptr,
	/* .esil_trap = */ nullptr,
	/* .esil_fini = */ nullptr,
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_ANAL,
	/* .data = */ &r_anal_plugin_ghidra,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr
#if R2_VERSION_MAJOR >= 4 && R2_VERSION_MINOR >= 2
	, "r2ghidra-dec"
#endif
};
#endif
