
#include "RCoreMutex.h"
#include <r_cons.h>

#include <cassert>

RCoreMutex::RCoreMutex(RCore *core) : caffeine_level(1), bed(nullptr), _core(core)
{
}

void RCoreMutex::sleepEnd()
{
	assert(caffeine_level >= 0);
	caffeine_level++;
	if(caffeine_level == 1)
	{
		r_cons_sleep_end(bed);
		bed = nullptr;
	}
}

void RCoreMutex::sleepEndForce()
{
	if(caffeine_level)
		return;
	sleepEnd();
}

void RCoreMutex::sleepBegin()
{
	assert(caffeine_level > 0);
	caffeine_level--;
	if(caffeine_level == 0)
		bed = r_cons_sleep_begin();
}