/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef RZ_GHIDRA_R2LOADIMAGE_H
#define RZ_GHIDRA_R2LOADIMAGE_H

#include "loadimage.hh"

#include <rz_core.h>

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

class RzCoreMutex;

class R2LoadImage : public LoadImage
{
	private:
		RzCoreMutex *const coreMutex;

	public:
		explicit R2LoadImage(RzCoreMutex *coreMutex);

		void loadFill(uint1 *ptr, int4 size, const Address &addr) override;
		string getArchType() const override;
		void adjustVma(long adjust) override;
};

#endif //RZ_GHIDRA_R2LOADIMAGE_H
