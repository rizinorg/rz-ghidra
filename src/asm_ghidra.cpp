/* radare - LGPL - Copyright 2020 - FXTi */

#include <r_lib.h>
#include <r_asm.h>
#include "SleighAsm.h"
#include "ArchMap.h"

static SleighAsm sasm;
static RIO *rio = nullptr;

//#define DEBUG_EXCEPTIONS

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	int r = 0;

	if(!a->cpu)
		return r;

#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		RBin *bin = a->binb.bin;

		if(!bin)
		{
			if(!rio)
			{
				rio = r_io_new();
				sasm.sleigh_id.clear(); // For newly created RIO, refresh SleighAsm.
			}
			else
				r_io_close_all(rio);

			RBuffer *tmp_buf = r_buf_new_with_bytes(buf, len);
			r_io_open_buffer(rio, tmp_buf, R_PERM_RWX, 0);
			r_buf_free(tmp_buf);
		}

		std::string sid = SleighIdFromArch(a->cpu, a->bits);
		sasm.init(sid.c_str(), bin? bin->iob.io : rio, SleighAsm::getConfig(a));
		sasm.check(bin? a->pc : 0, buf, len);
		r = sasm.disassemble(op, bin? a->pc : 0);
#ifndef DEBUG_EXCEPTIONS
	}
	catch(const LowlevelError &e)
	{
		r_strbuf_set(&op->buf_asm, e.explain.c_str());
		r = 1;
	}
#endif

	op->size = r;
	return r;
}

static bool fini(void *p)
{
	if(rio)
		r_io_free(rio);
	rio = nullptr;
}

RAsmPlugin r_asm_plugin_ghidra = {
	/* .name = */ "r2ghidra",
	/* .arch = */ "sleigh",
	/* .author = */ "FXTi",
	/* .version = */ nullptr,
	/* .cpus = */ nullptr,
	/* .desc = */ "SLEIGH Disassembler from Ghidra",
	/* .license = */ "GPL3",
	/* .user = */ nullptr,
	/* .bits = */ 0,
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
