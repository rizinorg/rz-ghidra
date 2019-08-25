
#ifndef R2GHIDRA_CODEXMLPARSE_H
#define R2GHIDRA_CODEXMLPARSE_H

#include "AnnotatedCode.h"

class Funcdata;

R_API RAnnotatedCode *ParseCodeXML(Funcdata *func, const char *xml);

#endif //R2GHIDRA_CODEXMLPARSE_H
