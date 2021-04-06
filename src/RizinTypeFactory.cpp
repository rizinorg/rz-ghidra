// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinTypeFactory.h"
#include "RizinArchitecture.h"

#include <rz_core.h>
#include <rz_type.h>

#include "RizinUtils.h"

RizinTypeFactory::RizinTypeFactory(RizinArchitecture *arch)
	: TypeFactory(arch),
	arch(arch)
{
	ctype = rz_type_ctype_new();
	if(!ctype)
		throw LowlevelError("Failed to create RParseCType");
}

RizinTypeFactory::~RizinTypeFactory()
{
	rz_type_ctype_free(ctype);
}

Datatype *RizinTypeFactory::addRizinStruct(RzBaseType *type, std::set<std::string> &stack_types)
{
	assert(type->kind == RZ_BASE_TYPE_KIND_STRUCT);

	std::vector<TypeField> fields;
	try
	{
		TypeStruct *r = getTypeStruct(type->name);
		void *it;
		rz_vector_foreach_cpp<RzTypeStructMember>(&type->struct_data.members, [&](RzTypeStructMember *member) {
			if(!member->type || !member->name)
				return;
			Datatype *member_type = fromCString(member->type, nullptr, &stack_types);
			if(!member_type)
			{
				arch->addWarning(std::string("Failed to match type ") + member->type + " of member " + member->name
						+ " in struct " + type->name);
				return;
			}

			// TODO: fix this super obsolete array stuff in struct sdb
			// if(elements > 0)
			// 	memberType = getTypeArray(elements, memberType);

			fields.push_back({
				(int4)member->offset,
				std::string(member->name),
				member_type
			});
		});
		if(fields.empty())
		{
			arch->addWarning(std::string("Struct ") + type->name + " has no members");
			return nullptr;
		}
		setFields(fields, r, 0, 0);
		return r;
	}
	catch(std::invalid_argument &e)
	{
		arch->addWarning(std::string("Failed to load struct ") + type->name);
		return nullptr;
	}
}

Datatype *RizinTypeFactory::addRizinEnum(RzBaseType *type)
{
	assert(type->kind == RZ_BASE_TYPE_KIND_ENUM);
	std::vector<std::string> namelist;
	std::vector<uintb> vallist;
	std::vector<bool> assignlist;
	rz_vector_foreach_cpp<RzTypeEnumCase>(&type->enum_data.cases, [&](RzTypeEnumCase *ceys) {
		if(!ceys->name)
			return;
		namelist.push_back(ceys->name);
		vallist.push_back(ceys->val);
		assignlist.push_back(true); // all enum values from rizin have explicit values
	});
	if(namelist.empty())
		return nullptr;
	try
	{
		auto enumType = getTypeEnum(type->name);
		setEnumValues(namelist, vallist, assignlist, enumType);
		return enumType;
	}
	catch(LowlevelError &e)
	{
		arch->addWarning(std::string("Failed to load enum ") + type->name + ", " + e.explain);
		return nullptr;
	}
}

Datatype *RizinTypeFactory::addRizinTypedef(RzBaseType *type, std::set<std::string> &stack_types)
{
	assert(type->kind == RZ_BASE_TYPE_KIND_TYPEDEF);
	if(!type->type)
		return nullptr;
	Datatype *resolved = fromCString(type->type, nullptr, &stack_types);
	if(!resolved)
		return nullptr;
	Datatype *typedefd = resolved->clone();
	setName(typedefd, type->name); // this removes the old name from the nametree
	setName(resolved, resolved->getName()); // add the old name back
	return typedefd;
}

Datatype *RizinTypeFactory::queryRizin(const string &n, std::set<std::string> &stack_types)
{
	if(stack_types.find(n) != stack_types.end())
	{
		arch->addWarning("Recursion detected while creating type " + n);
		return nullptr;
	}
	stack_types.insert(n);
	Datatype *r = nullptr;

	RzCoreLock core(arch->getCore());
	RzBaseType *type = rz_type_db_get_base_type(core->analysis->typedb, n.c_str());
	if(!type || !type->name)
	{
		if(type)
			rz_type_base_type_free(type);
		goto beach;
	}
	switch(type->kind)
	{
		case RZ_BASE_TYPE_KIND_STRUCT:
			r = addRizinStruct(type, stack_types);
			break;
		case RZ_BASE_TYPE_KIND_ENUM:
			r = addRizinEnum(type);
			break;
		case RZ_BASE_TYPE_KIND_TYPEDEF:
			r = addRizinTypedef(type, stack_types);
			break;
		// TODO: atomic too?
		default:
			break;
	}
	rz_type_base_type_free(type);
beach:
	stack_types.erase(n);
	return r;
}

Datatype *RizinTypeFactory::findById(const string &n, uint8 id, std::set<std::string> &stackTypes)
{
	Datatype *r = TypeFactory::findById(n, id);
	if(r)
		return r;
	return queryRizin(n, stackTypes);
}

Datatype *RizinTypeFactory::findById(const string &n, uint8 id)
{
	std::set<std::string> stackTypes; // to detect recursion
	return findById(n, id, stackTypes);
}

Datatype *RizinTypeFactory::fromCString(const string &str, string *error, std::set<std::string> *stackTypes)
{
	char *error_cstr = nullptr;
	RTypeCTypeType *type = rz_type_ctype_parse(ctype, str.c_str(), &error_cstr);
	if(error)
		*error = error_cstr ? error_cstr : "";
	if(!type)
		return nullptr;

	Datatype *r = fromCType(type, error, stackTypes);
	rz_type_ctype_type_free(type);
	return r;
}

Datatype *RizinTypeFactory::fromCType(const RTypeCTypeType *ctype, string *error, std::set<std::string> *stackTypes)
{
	switch(ctype->kind)
	{
		case RZ_TYPE_CTYPE_TYPE_KIND_IDENTIFIER:
		{
			if(ctype->identifier.kind == RZ_TYPE_CTYPE_IDENTIFIER_KIND_UNION)
			{
				if(error)
					*error = "Union types not supported in Decompiler";
				return nullptr;
			}

			Datatype *r = stackTypes ? findByName(ctype->identifier.name, *stackTypes) : findByName(ctype->identifier.name);
			if(!r)
			{
				if(error)
					*error = "Unknown type identifier " + std::string(ctype->identifier.name);
				return nullptr;
			}
			if(ctype->identifier.kind == RZ_TYPE_CTYPE_IDENTIFIER_KIND_STRUCT && r->getMetatype() != TYPE_STRUCT)
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of a struct";
				return nullptr;
			}
			if(ctype->identifier.kind == RZ_TYPE_CTYPE_IDENTIFIER_KIND_ENUM && !r->isEnumType())
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of an enum";
				return nullptr;
			}
			return r;
		}
		case RZ_TYPE_CTYPE_TYPE_KIND_POINTER:
		{
			Datatype *sub = fromCType(ctype->pointer.type, error, stackTypes);
			if(!sub)
				return nullptr;
			auto space = arch->getDefaultCodeSpace();
			return this->getTypePointer(space->getAddrSize(), sub, space->getWordSize());
		}
		case RZ_TYPE_CTYPE_TYPE_KIND_ARRAY:
		{
			Datatype *sub = fromCType(ctype->array.type, error, stackTypes);
			if(!sub)
				return nullptr;
			return this->getTypeArray(ctype->array.count, sub);
		}
	}
	return nullptr;
}
