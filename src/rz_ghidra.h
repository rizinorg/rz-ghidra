#ifndef RZ_GHIDRA_H
#define RZ_GHIDRA_H

#include <rz_util/rz_annotated_code.h>
#include <rz_core.h>

RZ_API RzAnnotatedCode *rz_ghidra_decompile_annotated_code(RzCore *core, ut64 addr);

#endif //RZ_GHIDRA_H
