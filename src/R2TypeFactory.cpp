/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2TypeFactory.h"
#include "R2Architecture.h"

R2TypeFactory::R2TypeFactory(R2Architecture *arch)
	: TypeFactory(arch),
	arch(arch)
{
}

Datatype *R2TypeFactory::findById(const string &n, uint8 id)
{
	eprintf("type queried: %s, id: %llu\n", n.c_str(), (unsigned long long)id);
	return TypeFactory::findById(n, id);
}