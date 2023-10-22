// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_CODEXMLPARSE_H
#define RZ_GHIDRA_CODEXMLPARSE_H

#include <rz_util/rz_annotated_code.h>

namespace ghidra {
class Funcdata;
};

RZ_API RzAnnotatedCode *ParseCodeXML(ghidra::Funcdata *func, const char *xml);

#endif //RZ_GHIDRA_CODEXMLPARSE_H
