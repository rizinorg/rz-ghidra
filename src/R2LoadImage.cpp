// SPDX-License-Identifier: LGPL-3.0-or-later

#include "R2LoadImage.h"
#include "R2Architecture.h"

R2LoadImage::R2LoadImage(RzCoreMutex *coreMutex)
	: LoadImage("radare2_program"),
	coreMutex(coreMutex)
{
}

void R2LoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr)
{
	RzCoreLock core(coreMutex);
	rz_io_read_at(core->io, addr.getOffset(), ptr, size);
}

string R2LoadImage::getArchType() const
{
	return "radare2";
}

void R2LoadImage::adjustVma(long adjust)
{
	throw LowlevelError("Cannot adjust radare2 virtual memory");
}
