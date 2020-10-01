/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef RZ_GHIDRA_ARCHMAP_H
#define RZ_GHIDRA_ARCHMAP_H

#include <sleigh_arch.hh>

#include <rz_core.h>

#include <string>

/**
 * Match sleigh id from whatever is currently configured.
 * For regular rizin plugins, guess the matching sleigh id,
 * for the specific sleigh plugin, same as SleighIdFromSleighAsmConfig()
 */
std::string SleighIdFromCore(RzCore *core);

/**
 * Match sleigh id from sleigh-plugin specific settings (asm.cpu)
 */
std::string SleighIdFromSleighAsmConfig(const char *cpu, int bits, bool bigendian, const vector<LanguageDescription> &langs);

#endif
