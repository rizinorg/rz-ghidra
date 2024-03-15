// SPDX-FileCopyrightText: 2024 Crabtux <crabtux@mail.ustc.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "PcodeFixupPreprocessor.h"

#include <funcdata.hh>
#include <flow.hh>
#include <override.hh>

using namespace ghidra;

void PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(RzAnalysisFunction *function, Funcdata *func, RzCore *core, RizinArchitecture &arch)
{
	RzList *refs = rz_analysis_function_get_xrefs_from(function);

	RzListIter *it;
	RzAnalysisXRef *xref;

	// C++ has more strict type checking than C, which stops us from implicitly casting void * to RzListIter *.
	// Expand the rz_list_foreach macro manually. 
	if (refs) for (it = refs->head; it && (xref = (RzAnalysisXRef *)it->elem, 1); it = it->next)
	{
		// To ensure the instruction is a `jmp` instruction
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CODE)
			continue;

		// If the target location is outside of the current function, and it is a imported function, then do the patch.
		// FIXME: Use librz to confirm the target location is an imported function.
		RzAnalysisFunction *targetFunction = rz_analysis_get_fcn_in(core->analysis, xref->to, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (targetFunction == NULL)
		{
			func->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), xref->from), Override::CALL_RETURN);
		}
	}
}
