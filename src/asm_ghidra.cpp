/* radare - LGPL - Copyright 2020 - FXTi */

#include <r_lib.h>
#include <r_asm.h>
#include "SleighAsm.h"

static SleighAsm sasm;

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    sasm.init (a);

    int r = sasm.disassemble (op, a->pc);
    op->size = r;
    return r;
}

RAsmPlugin r_asm_plugin_ghidra = {
    .name = "r2ghidra",
    .arch = "sleigh",
    .author = "FXTi",
    .version = "0.0.1",
    .desc = "SLEIGH Disassembler from Ghidra",
	.license = "GPL3",
    .disassemble = &disassemble,
    /*.init = */
	/*.fini = */ 
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_ASM,
	/* .data = */ &r_asm_plugin_ghidra,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr
#if R2_VERSION_MAJOR >= 4 && R2_VERSION_MINOR >= 2
	, "r2ghidra-dec"
#endif
};
#endif