/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_ARCHMAP_H
#define R2GHIDRA_ARCHMAP_H

#ifdef __cplusplus
extern "C" {
#endif
#include <r_core.h>
#ifdef __cplusplus
}
#endif

#include <string>

std::string SleighIdFromCore(RCore *core);

#endif
