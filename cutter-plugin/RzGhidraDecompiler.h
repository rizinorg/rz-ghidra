// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RZ_GHIDRADECOMPILER_H
#define RZ_GHIDRA_RZ_GHIDRADECOMPILER_H

#include "Decompiler.h"
#include "RizinTask.h"

class RzGhidraDecompiler: public Decompiler
{
	enum DecompilerState {DecompilerRunning, DecompilerFinished};
	private:
		DecompilerState task;

	public:
		RzGhidraDecompiler(QObject *parent = nullptr);
		void decompileAt(RVA addr) override;
		bool isRunning() override				{ return task == DecompilerRunning; }
};

#endif //RZ_GHIDRA_RZ_GHIDRADECOMPILER_H
