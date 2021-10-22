// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinLoadImage.h"
#include "RizinArchitecture.h"
#include "RizinUtils.h"

RizinLoadImage::RizinLoadImage(RzCoreMutex *core_mutex, AddrSpaceManager *addr_space_manager)
	: LoadImage("rizin_program"),
	core_mutex(core_mutex),
	addr_space_manager(addr_space_manager)
{
}

void RizinLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr)
{
	RzCoreLock core(core_mutex);
	rz_io_read_at(core->io, addr.getOffset(), ptr, size);
}

void RizinLoadImage::getReadonly(RangeList &list) const
{
	auto space = addr_space_manager->getDefaultCodeSpace();
	RzCoreLock core(core_mutex);
	rz_vector_foreach_cpp<RzSkylineItem>(&core->io->map_skyline.v, [&](RzSkylineItem *skyscraper) {
		auto map = reinterpret_cast<RzIOMap *>(skyscraper->user);
		if((map->perm & RZ_PERM_W) || !skyscraper->itv.size)
			return;
		list.insertRange(space, skyscraper->itv.addr, skyscraper->itv.addr + skyscraper->itv.size - 1);
	});
}

string RizinLoadImage::getArchType() const
{
	return "rizin";
}

void RizinLoadImage::adjustVma(long adjust)
{
	throw LowlevelError("Cannot adjust rizin virtual memory");
}
