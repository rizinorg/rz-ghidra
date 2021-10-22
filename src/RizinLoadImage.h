// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinLOADIMAGE_H
#define RZ_GHIDRA_RizinLOADIMAGE_H

#include "loadimage.hh"

#include <rz_core.h>

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

class RzCoreMutex;

class RizinLoadImage : public LoadImage
{
	private:
		RzCoreMutex *const core_mutex;
		AddrSpaceManager *addr_space_manager;

	public:
		explicit RizinLoadImage(RzCoreMutex *core_mutex, AddrSpaceManager *addr_space_manager);

		void loadFill(uint1 *ptr, int4 size, const Address &addr) override;
		void getReadonly(RangeList &list) const override;
		string getArchType() const override;
		void adjustVma(long adjust) override;
};

#endif //RZ_GHIDRA_RizinLOADIMAGE_H
