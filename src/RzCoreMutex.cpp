// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RzCoreMutex.h"
#include <rz_core.h>
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
		rz_interrupt_sleep_end(_core->intr, bed);
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
		bed = rz_interrupt_sleep_begin(_core->intr);
}
