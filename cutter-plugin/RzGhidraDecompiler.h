// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZGHIDRA_RZGHIDRADECOMPILER_H
#define RZGHIDRA_RZGHIDRADECOMPILER_H

#include "Decompiler.h"
#include "RzTask.h"

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

#endif //RZGHIDRA_RZGHIDRADECOMPILER_H
