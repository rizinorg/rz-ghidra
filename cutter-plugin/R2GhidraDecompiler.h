/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2GHIDRADECOMPILER_H
#define R2GHIDRA_R2GHIDRADECOMPILER_H

#include "Decompiler.h"
#include "R2Task.h"

class R2GhidraDecompiler: public Decompiler
{
	private:
		R2Task *task;

	public:
		R2GhidraDecompiler(QObject *parent = nullptr);
		void decompileAt(RVA addr) override;
		bool isRunning() override				{ return task != nullptr; }
};

#endif //R2GHIDRA_R2GHIDRADECOMPILER_H
