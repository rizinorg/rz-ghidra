// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RzLoadImage.h"
#include "RzArchitecture.h"

RzLoadImage::RzLoadImage(RzCoreMutex *coreMutex)
	: LoadImage("rizin_program"),
	coreMutex(coreMutex)
{
}

void RzLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr)
{
	RzCoreLock core(coreMutex);
	rz_io_read_at(core->io, addr.getOffset(), ptr, size);
}

string RzLoadImage::getArchType() const
{
	return "rizin";
}

void RzLoadImage::adjustVma(long adjust)
{
	throw LowlevelError("Cannot adjust rizin virtual memory");
}
