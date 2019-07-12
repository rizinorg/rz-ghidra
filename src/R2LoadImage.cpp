/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2LoadImage.h"

R2LoadImage::R2LoadImage(RCore *core)
	: LoadImage("radare2_program"),
	core(core)
{
}

void R2LoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr)
{
	// TODO: sync
	printf("r2 io queried: 0x%" PFMT64x ", size: %d\n", (ut64)addr.getOffset(), (int)size);
	r_io_read_at(core->io, addr.getOffset(), ptr, size);
}

string R2LoadImage::getArchType() const
{
	return "radare2";
}

void R2LoadImage::adjustVma(long adjust)
{
	throw LowlevelError("Cannot adjust radare2 virtual memory");
}
