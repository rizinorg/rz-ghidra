// SPDX-FileCopyrightText: 2024 Crabtux <crabtux@mail.ustc.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef PCODE_PREPROCESSOR_H
#define PCODE_PREPROCESSOR_H

#include "RizinArchitecture.h"

class PcodeFixupPreprocessor
{
    public:
        static void fixupSharedReturnCall(RizinArchitecture &arch, RzCore *core);
};

#endif