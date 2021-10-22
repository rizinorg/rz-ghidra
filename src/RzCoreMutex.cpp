// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RzCoreMutex.h"
#include <rz_cons.h>

#include <cassert>

RzCoreMutex::RzCoreMutex(RzCore *core) : caffeine_level(1), bed(nullptr), _core(core)
{
}

void RzCoreMutex::sleepEnd()
{
	assert(caffeine_level >= 0);
	caffeine_level++;
	if(caffeine_level == 1)
	{
		rz_cons_sleep_end(bed);
		bed = nullptr;
	}
}

void RzCoreMutex::sleepEndForce()
{
	if(caffeine_level)
		return;
	sleepEnd();
}

void RzCoreMutex::sleepBegin()
{
	assert(caffeine_level > 0);
	caffeine_level--;
	if(caffeine_level == 0)
		bed = rz_cons_sleep_begin();
}
