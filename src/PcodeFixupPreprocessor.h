// SPDX-FileCopyrightText: 2024 Crabtux <crabtux@mail.ustc.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef PCODE_PREPROCESSOR_H
#define PCODE_PREPROCESSOR_H

#include "RizinArchitecture.h"

#include <rz_core.h>

class PcodeFixupPreprocessor
{
	public:
		static void fixupSharedReturnJumpToRelocs(RzAnalysisFunction *function, ghidra::Funcdata *func, RzCore *core, RizinArchitecture &arch);
};

#endif