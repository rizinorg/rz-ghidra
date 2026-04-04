// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <rz_lib.h>
#include <rz_asm.h>
#include "SleighAsm.h"
#include "rz_ghidra_internal.h"

using namespace ghidra;

static SleighAsm sasm;
static RzIO *rio = nullptr;

//#define DEBUG_EXCEPTIONS

static int disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len)
{
	int r = 0;

	if(!rz_asm_get_cpu(a))
		return r;

#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		sasm.init(rz_asm_get_cpu(a), rz_asm_get_bits(a), rz_asm_is_big_endian_set(a), SleighAsm::getConfig(a));
		r = sasm.disassemble(op, rz_asm_get_pc(a), buf, len);
#ifndef DEBUG_EXCEPTIONS
	}
	catch(const LowlevelError &e)
	{
		rz_strbuf_set(&op->buf_asm, e.explain.c_str());
		r = 1;
	}
#endif

	op->size = r;
	return r;
}

static bool init(void **user)
{
	rz_ghidra_lib_init();
	return true;
}

static bool fini(void *p)
{
	rz_ghidra_lib_fini();
	if(rio)
		rz_io_free(rio);
	rio = nullptr;
	return true;
}

RzAsmPlugin rz_asm_plugin_ghidra = {
	/* .name = */ "ghidra",
	/* .arch = */ "sleigh",
	/* .author = */ "FXTi",
	/* .version = */ nullptr,
	/* .cpus = */ nullptr,
	/* .desc = */ "SLEIGH Disassembler from Ghidra",
	/* .license = */ "LGPL3",
	/* .bits = */ 8 | 16 | 32 | 64,
	/* .endian = */ 0,
	/* .init = */ &init,
	/* .fini = */ &fini,
	/* .disassemble = */ &disassemble,
	/* .assemble = */ nullptr,
	/* .modify */ nullptr,
	/* .mnemonics = */ nullptr,
	/* .features = */ nullptr
};

#ifndef CORELIB
extern "C" {
RZ_API RzLibStruct rizin_plugin = {
	/* .type = */ RZ_LIB_TYPE_ASM,
	/* .data = */ &rz_asm_plugin_ghidra,
	/* .version = */ RZ_VERSION,
	/* .free = */ nullptr,
};
}
#endif
