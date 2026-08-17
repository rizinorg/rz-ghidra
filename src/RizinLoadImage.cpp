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
	rz_io_read_at_mapped(core->io, addr.getOffset(), ptr, size);
}

namespace {

struct ImportSlotCtx {
	RangeList *list;
	AddrSpace *space;
	RzIO *io;
	ut64 slot_size;
};

// Punch one import slot out of the read-only ranges. The loader owns a slot's
// value, so it is a property of a process and never a constant of the program.
// Unbound it is a hint/name table RVA; in a dump, one run's resolved address.
bool subtract_import_slot(RzFlagItem *fi, void *user)
{
	auto ctx = reinterpret_cast<ImportSlotCtx *>(user);
	RzIOMap *map = rz_io_map_get(ctx->io, fi->offset);
	if(!map || !map->user)
		return true;
	auto info = reinterpret_cast<RzCoreIOMapInfo *>(map->user);
	// On ELF these flags sit on PLT stubs, not slots; the GOT slots behind them
	// already resolve by name through their relocs.
	if(info->perm_orig & RZ_PERM_X)
		return true;
	// fi->size is not the slot extent: PE import flags carry 0, ELF ones the
	// length of the PLT stub.
	ut64 last = fi->offset + ctx->slot_size - 1;
	if(last < fi->offset) // slot at the very top of the space
		return true;
	ctx->list->removeRange(ctx->space, fi->offset, last);
	return true;
}

} // namespace

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

	// The loop above judges read-only from permissions alone, which sweeps in the
	// PE IAT because it lives in .rdata. Subtract those slots again.
	RzSpace *imports_space = rz_flag_space_get(core->flags, RZ_FLAGS_FS_IMPORTS);
	if(imports_space)
	{
		ImportSlotCtx ctx = { &list, space, core->io, space->getAddrSize() };
		rz_flag_foreach_space(core->flags, imports_space, subtract_import_slot, &ctx);
	}
}

string RizinLoadImage::getArchType() const
{
	return "rizin";
}

void RizinLoadImage::adjustVma(long adjust)
{
	throw LowlevelError("Cannot adjust rizin virtual memory");
}
