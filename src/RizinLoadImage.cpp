// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinLoadImage.h"
#include "RizinArchitecture.h"
#include "RizinUtils.h"

using namespace ghidra;

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
	RzCoreLock core(core_mutex);
	std::set<RzCoreFile *> cf_visited;
	auto space = addr_space_manager->getDefaultCodeSpace();
	rz_vector_foreach_cpp<RzSkylineItem>(&core->io->map_skyline.v, [&](RzSkylineItem *skyscraper) {
		auto map = reinterpret_cast<RzIOMap *>(skyscraper->user);
		if(!map->user || !skyscraper->itv.size)
			return;
		auto info = reinterpret_cast<RzCoreIOMapInfo *>(map->user);
		if(!info->perm_orig || (info->perm_orig & RZ_PERM_W))
		{
			// Special case: objc maps pointers to e.g. the method name strings as rw unfortunately,
			// but we want to have them propagated as constants.
			// Similar to ObjectiveC2_ClassAnalyzer.setDataAndRefBlocksReadOnly, we just look for the
			// sections by their name and force the ranges to read-only. This is under the assumption
			// in here that if a RzBinMap comes from a corefile, then all of its RzBinFiles' sections
			// are mapped at their contained vaddrs.
			if(cf_visited.find(info->cf) != cf_visited.end())
				return;
			cf_visited.insert(info->cf);
			rz_pvector_foreach_cpp<RzBinFile>(&info->cf->binfiles, [&](RzBinFile *bf) {
				if(!bf->o || !bf->o->sections)
					return true;
				rz_pvector_foreach_cpp<RzBinSection>(bf->o->sections, [&](RzBinSection *sec) {
					if(!sec->name || !sec->vsize)
						return true;
					if(strstr(sec->name, "__objc_data") || strstr(sec->name, "__objc_classrefs") || strstr(sec->name, "__objc_msgrefs") ||
						strstr(sec->name, "__objc_selrefs") || strstr(sec->name, "__objc_superrefs") || strstr(sec->name, "__objc_protorefs"))
						list.insertRange(space, sec->vaddr, sec->vaddr + sec->vsize - 1);
					return true;
				});
				return true;
			});
			return;
		}
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
