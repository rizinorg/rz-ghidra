/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2GhidraDecompiler.h"
#include "../src/r2ghidra.h"

#include <Cutter.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

R2GhidraDecompiler::R2GhidraDecompiler(QObject *parent)
	: Decompiler("r2ghidra", "Ghidra", parent)
{
	task = DecompilerFinished;
}

void R2GhidraDecompiler::decompileAt(ut64 addr)
{
	task = DecompilerRunning;
	RAnnotatedCode *code = r2ghidra_decompile_annotated_code(Core()->core(), addr);
	emit finished(code); //Here, we emit RAnnotatedCode *code or by value
	task = DecompilerFinished;
}
