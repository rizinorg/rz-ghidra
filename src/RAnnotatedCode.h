/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_RANNOTATEDCODE_H
#define R2GHIDRA_RANNOTATEDCODE_H

#include <r_util/r_annotated_code.h>
#include <r_core.h>

R_API RAnnotatedCode* DecompileToRAnnotatedCode(RCore *core);

#endif //R2GHIDRA_RANNOTATEDCODE_H
