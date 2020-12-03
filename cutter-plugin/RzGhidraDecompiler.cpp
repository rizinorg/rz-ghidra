// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RzGhidraDecompiler.h"
#include "../src/rz_ghidra.h"

#include <Cutter.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

RzGhidraDecompiler::RzGhidraDecompiler(QObject *parent)
	: Decompiler("rz-ghidra", "Ghidra", parent)
{
	task = DecompilerFinished;
}

void RzGhidraDecompiler::decompileAt(ut64 addr)
{
	task = DecompilerRunning;
	RzAnnotatedCode *code = rz_ghidra_decompile_annotated_code(Core()->core(), addr);
	emit finished(code); //Here, we emit RzAnnotatedCode *code or by value
	task = DecompilerFinished;
}
