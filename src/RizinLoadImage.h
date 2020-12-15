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
		RzCoreMutex *const coreMutex;

	public:
		explicit RizinLoadImage(RzCoreMutex *coreMutex);

		void loadFill(uint1 *ptr, int4 size, const Address &addr) override;
		string getArchType() const override;
		void adjustVma(long adjust) override;
};

#endif //RZ_GHIDRA_RizinLOADIMAGE_H
