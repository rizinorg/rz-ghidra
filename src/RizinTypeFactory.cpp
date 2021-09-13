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
}

RizinTypeFactory::~RizinTypeFactory()
{
}

Datatype *RizinTypeFactory::addRizinStruct(RzBaseType *type, std::set<std::string> &stack_types)
{
	assert(type->kind == RZ_BASE_TYPE_KIND_STRUCT);

	std::vector<TypeField> fields;
	try
	{
		RzCoreLock core(arch->getCore());
		ut64 offset = 0;
		TypeStruct *r = getTypeStruct(type->name);
		void *it;
		rz_vector_foreach_cpp<RzTypeStructMember>(&type->struct_data.members, [&](RzTypeStructMember *member) {
			if(!member->type || !member->name)
				return;
			Datatype *member_type = fromRzType(member->type, nullptr, &stack_types);
			if(!member_type)
			{
				char *tstr = rz_type_as_string(core->analysis->typedb, member->type);
				arch->addWarning(std::string("Failed to match type ") + (tstr ? tstr : "?") + " of member " + member->name
						+ " in struct " + type->name);
				rz_mem_free(tstr);
				return;
			}

			// TODO: fix this super obsolete array stuff in struct sdb
			// if(elements > 0)
			// 	memberType = getTypeArray(elements, memberType);

			fields.push_back({
				(int4)offset, // Currently, this is 0 most of the time: member->offset,
				std::string(member->name),
				member_type
			});

			// TODO: right now, we track member offset ourselves
			// which means all structs are assumed to be packed.
			// This should be changed if there is a clear notion of the offset in rizin at some point.
			offset += rz_type_db_get_bitsize(core->analysis->typedb, member->type) / 8;
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
	Datatype *resolved = fromRzType(type->type, nullptr, &stack_types);
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
		goto beach;
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
beach:
	stack_types.erase(n);
	return r;
}

Datatype *RizinTypeFactory::findById(const string &n, uint8 id, int4 sz, std::set<std::string> &stackTypes)
{
	Datatype *r = TypeFactory::findById(n, id, sz);
	if(r)
		return r;
	return queryRizin(n, stackTypes);
}

Datatype *RizinTypeFactory::findById(const string &n, uint8 id, int4 sz)
{
	std::set<std::string> stackTypes; // to detect recursion
	return findById(n, id, sz, stackTypes);
}

Datatype *RizinTypeFactory::fromRzType(const RzType *ctype, string *error, std::set<std::string> *stackTypes)
{
	switch(ctype->kind)
	{
		case RZ_TYPE_KIND_IDENTIFIER:
		{
			if(ctype->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNION)
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
			if(ctype->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_STRUCT && r->getMetatype() != TYPE_STRUCT)
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of a struct";
				return nullptr;
			}
			if(ctype->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_ENUM && !r->isEnumType())
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of an enum";
				return nullptr;
			}
			return r;
		}
		case RZ_TYPE_KIND_POINTER:
		{
			Datatype *sub = fromRzType(ctype->pointer.type, error, stackTypes);
			if(!sub)
				return nullptr;
			auto space = arch->getDefaultCodeSpace();
			return this->getTypePointer(space->getAddrSize(), sub, space->getWordSize());
		}
		case RZ_TYPE_KIND_ARRAY:
		{
			Datatype *sub = fromRzType(ctype->array.type, error, stackTypes);
			if(!sub)
				return nullptr;
			return this->getTypeArray(ctype->array.count, sub);
		}
		case RZ_TYPE_KIND_CALLABLE:
		{
			// TODO!
		}
	}
	return nullptr;
}
