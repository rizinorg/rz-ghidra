/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2GHIDRADECOMPILER_H
#define R2GHIDRA_R2GHIDRADECOMPILER_H

#include "Decompiler.h"

class R2GhidraDecompiler: public Decompiler
{
	public:
		R2GhidraDecompiler(QObject *parent = nullptr);
		DecompiledCode decompileAt(RVA addr) override;
};

#endif //R2GHIDRA_R2GHIDRADECOMPILER_H
