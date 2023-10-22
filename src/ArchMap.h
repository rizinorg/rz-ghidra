// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019 Ayman Khamouma <kamou.k@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

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
RZ_API std::string SleighIdFromCore(RzCore *core);

/**
 * Match sleigh id from sleigh-plugin specific settings (asm.cpu)
 */
RZ_API std::string SleighIdFromSleighAsmConfig(const char *cpu, int bits, bool bigendian, const std::vector<ghidra::LanguageDescription> &langs);

#endif
