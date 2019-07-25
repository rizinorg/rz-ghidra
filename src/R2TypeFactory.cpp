/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2TypeFactory.h"
#include "R2Architecture.h"

#include <r_parse.h>

R2TypeFactory::R2TypeFactory(R2Architecture *arch)
	: TypeFactory(arch),
	arch(arch)
{
	ctype = r_parse_ctype_new();
	if(!ctype)
		throw LowlevelError("Failed to create RParseCType");
}

R2TypeFactory::~R2TypeFactory()
{
	r_parse_ctype_free(ctype);
}

Datatype *R2TypeFactory::findById(const string &n, uint8 id)
{
	//eprintf("type queried: %s, id: %llu\n", n.c_str(), (unsigned long long)id);
	return TypeFactory::findById(n, id);
}

Datatype *R2TypeFactory::fromCString(const string &str, string *error)
{
	char *error_cstr = nullptr;
	RParseCTypeType *type = r_parse_ctype_parse(ctype, str.c_str(), &error_cstr);
	if(error)
		*error = error_cstr ? error_cstr : "";
	if(!type)
		return nullptr;

	Datatype *r = fromCType(type, error);
	r_parse_ctype_type_free(type);
	return r;
}

Datatype *R2TypeFactory::fromCType(const RParseCTypeType *ctype, string *error)
{
	switch(ctype->kind)
	{
		case RParseCTypeType::R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER:
		{
			Datatype *r = findByName(ctype->identifier.name);
			if(!r && error)
				*error = "Unknown type identifier " + std::string(ctype->identifier.name);
			return r;
		}
		case RParseCTypeType::R_PARSE_CTYPE_TYPE_KIND_POINTER:
		{
			Datatype *sub = fromCType(ctype->pointer.type);
			if(!sub)
				return nullptr;
			auto space = arch->getDefaultSpace();
			return this->getTypePointer(space->getAddrSize(), sub, space->getWordSize());
		}
		case RParseCTypeType::R_PARSE_CTYPE_TYPE_KIND_ARRAY:
		{
			Datatype *sub = fromCType(ctype->array.type);
			if(!sub)
				return nullptr;
			return this->getTypeArray(ctype->array.count, sub);
		}
	}
	return nullptr;
}