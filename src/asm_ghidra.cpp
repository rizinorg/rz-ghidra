/* radare - LGPL - Copyright 2020 - FXTi */

#include <rz_lib.h>
#include <rz_asm.h>
#include "SleighAsm.h"

static SleighAsm sasm;
static RzIO *rio = nullptr;

//#define DEBUG_EXCEPTIONS

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len)
{
	int r = 0;

	if(!a->cpu)
		return r;

#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		RzBin *bin = a->binb.bin;

		if(!bin)
		{
			if(!rio)
			{
				rio = rz_io_new();
				sasm.sleigh_id.clear(); // For newly created RzIO, refresh SleighAsm.
			}
			else
				rz_io_close_all(rio);

			RzBuffer *tmp_buf = rz_buf_new_with_bytes(buf, len);
			rz_io_open_buffer(rio, tmp_buf, RZ_PERM_RWX, 0);
			rz_buf_free(tmp_buf);
		}

		sasm.init(a->cpu, a->bits, a->big_endian, bin? bin->iob.io : rio, SleighAsm::getConfig(a));
		sasm.check(bin? a->pc : 0, buf, len);
		r = sasm.disassemble(op, bin? a->pc : 0);
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

static bool fini(void *p)
{
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
	/* .license = */ "GPL3",
	/* .user = */ nullptr,
	/* .bits = */ 8 | 16 | 32 | 64,
	/* .endian = */ 0,
	/* .init = */ nullptr,
	/* .fini = */ &fini,
	/* .disassemble = */ &disassemble,
	/* .assemble = */ nullptr,
	/* .modify */ nullptr,
	/* .mnemonics = */ nullptr,
	/* .features = */ nullptr
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
RZ_API RzLibStruct rizin_plugin = {
	/* .type = */ RZ_LIB_TYPE_ASM,
	/* .data = */ &rz_asm_plugin_ghidra,
	/* .version = */ RZ_VERSION,
	/* .free = */ nullptr
#if RZ_VERSION_MAJOR >= 4 && RZ_VERSION_MINOR >= 2
	, "rz-ghidra"
#endif
};
#endif
