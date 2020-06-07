#ifndef R2GHIDRA_H
#define R2GHIDRA_H

#include <r_util/r_annotated_code.h>
#include <r_core.h>

R_API RAnnotatedCode *r2ghidra_decompile_annotated_code(RCore *core, ut64 addr);

#endif //R2GHIDRA_H
