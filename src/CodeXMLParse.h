/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef RZ_GHIDRA_CODEXMLPARSE_H
#define RZ_GHIDRA_CODEXMLPARSE_H

#include <rz_util/rz_annotated_code.h>

class Funcdata;

RZ_API RAnnotatedCode *ParseCodeXML(Funcdata *func, const char *xml);

#endif //RZ_GHIDRA_CODEXMLPARSE_H
