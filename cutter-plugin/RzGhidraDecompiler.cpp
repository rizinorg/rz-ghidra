/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "RzGhidraDecompiler.h"
#include "../src/rz_ghidra.h"

#include <Cutter.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

RzGhidraDecompiler::RzGhidraDecompiler(QObject *parent)
	: Decompiler("r2ghidra", "Ghidra", parent)
{
	task = DecompilerFinished;
}

void RzGhidraDecompiler::decompileAt(ut64 addr)
{
	task = DecompilerRunning;
	RzAnnotatedCode *code = r2ghidra_decompile_annotated_code(Core()->core(), addr);
	emit finished(code); //Here, we emit RzAnnotatedCode *code or by value
	task = DecompilerFinished;
}
