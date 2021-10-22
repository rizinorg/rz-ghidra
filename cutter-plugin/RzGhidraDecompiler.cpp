// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
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
	task = nullptr;
}

void RzGhidraDecompiler::decompileAt(ut64 addr)
{
	if(task)
		return;
	task = new RizinFunctionTask([addr](RzCore *core) {
		return rz_ghidra_decompile_annotated_code(core, addr);
	});
	connect(task, &RizinFunctionTask::finished, this, [this]() {
		auto res = reinterpret_cast<RzAnnotatedCode *>(task->getResult());
		task = nullptr;
		emit finished(res);
	});
	task->startTask();
}
