/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_CODEXMLPARSE_H
#define R2GHIDRA_CODEXMLPARSE_H

// #include "AnnotatedCode.h"
#include <r_util/AnnotatedCode.h>

class Funcdata;

R_API RAnnotatedCode *ParseCodeXML(Funcdata *func, const char *xml);

#endif //R2GHIDRA_CODEXMLPARSE_H
