// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinLoadImage.h"
#include "RizinArchitecture.h"

RizinLoadImage::RizinLoadImage(RzCoreMutex *coreMutex)
	: LoadImage("rizin_program"),
	coreMutex(coreMutex)
{
}

void RizinLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr)
{
	RzCoreLock core(coreMutex);
	rz_io_read_at(core->io, addr.getOffset(), ptr, size);
}

string RizinLoadImage::getArchType() const
{
	return "rizin";
}

void RizinLoadImage::adjustVma(long adjust)
{
	throw LowlevelError("Cannot adjust rizin virtual memory");
}
