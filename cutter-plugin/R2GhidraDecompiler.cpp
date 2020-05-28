/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2GhidraDecompiler.h"
#include "../src/RAnnotatedCode.h"

#include <Cutter.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

R2GhidraDecompiler::R2GhidraDecompiler(QObject *parent)
	: Decompiler("r2ghidra", "Ghidra", parent)
{
	task = nullptr;
}

void R2GhidraDecompiler::decompileAt(RVA addr)
{
	RAnnotatedCode *code = DecompileToRAnnotatedCode(Core()->core());
	emit finished(code); //Here, we emit RAnnotatedCode *code or by value
}
