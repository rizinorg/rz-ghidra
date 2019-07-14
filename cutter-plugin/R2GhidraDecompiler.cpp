/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2GhidraDecompiler.h"

#include <Cutter.h>

R2GhidraDecompiler::R2GhidraDecompiler(QObject *parent)
	: Decompiler("r2ghidra", "Ghidra", parent)
{
}

DecompiledCode R2GhidraDecompiler::decompileAt(RVA addr)
{
	DecompiledCode code;
	auto lines = Core()->cmd("pdg @ " + QString::number(addr)).split('\n');
	code.lines.reserve(lines.size());
	for(const auto &line : lines)
		code.lines.append(DecompiledCode::Line(line));
	return code;
}
