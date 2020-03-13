/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2TypeFactory.h"
#include "R2Architecture.h"

#include <r_parse.h>
#include <r_core.h>

#include "R2Utils.h"

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


std::vector<std::string> splitSdbArray(const std::string& str)
{
	std::stringstream ss(str);
	std::string token;
	std::vector<std::string> r;
	while(std::getline(ss, token, SDB_RS))
		r.push_back(token);
	return r;
}

Datatype *R2TypeFactory::queryR2Struct(const string &n)
{
	RCoreLock core(arch->getCore());

	Sdb *sdb = core->anal->sdb_types;

	// TODO: We need an API for this in r2

	const char *members = sdb_const_get(sdb, ("struct." + n).c_str(), nullptr);
	if(!members)
		return nullptr;

	std::vector<TypeField> fields;
	std::stringstream membersStream(members);
	std::string memberName;
	while(std::getline(membersStream, memberName, SDB_RS))
	{
		const char *memberContents = sdb_const_get(sdb, ("struct." + n + "." + memberName).c_str(), nullptr);
		if(!memberContents)
			continue;
		auto memberTokens = splitSdbArray(memberContents);
		if(memberTokens.size() < 3)
			continue;
		auto memberTypeName = memberTokens[0];
		int4 offset = std::stoi(memberTokens[1]);
		int4 elements = std::stoi(memberTokens[2]);
		Datatype *memberType = fromCString(memberTypeName);
		if(!memberType)
		{
			arch->addWarning("Failed to match type " + memberTypeName + " of member " + memberName + " in struct " + n);
			continue;
		}

		if(elements > 0)
			memberType = getTypeArray(elements, memberType);

		fields.push_back({
			offset,
			memberName,
			memberType
		});
	}

	TypeStruct *r = getTypeStruct(n);
	setFields(fields, r, 0);
	return r;
}

Datatype *R2TypeFactory::queryR2Enum(const string &n)
{
	RCoreLock core(arch->getCore());
	RList *members = r_type_get_enum(core->anal->sdb_types, n.c_str());
	if(!members)
		return nullptr;

	std::vector<std::string> namelist;
	std::vector<uintb> vallist;
	std::vector<bool> assignlist;

	r_list_foreach_cpp<RTypeEnum>(members, [&](RTypeEnum *member) {
		if(!member->name || !member->val)
			return;
		uintb val = std::stoull(member->val, nullptr, 0);
		namelist.push_back(member->name);
		vallist.push_back(val);
		assignlist.push_back(true); // all enum values from r2 have explicit values
	});
	r_list_free (members);

	if(namelist.empty())
		return nullptr;

	auto enumType = getTypeEnum(n);
	setEnumValues(namelist, vallist, assignlist, enumType);
	return enumType;
}

Datatype *R2TypeFactory::queryR2(const string &n, std::set<std::string> &stackTypes)
{
	if(stackTypes.find(n) != stackTypes.end())
	{
		arch->addWarning("Recursion detected while creating type " + n);
		return nullptr;
	}
	stackTypes.insert(n);

	RCoreLock core(arch->getCore());
	int kind = r_type_kind(core->anal->sdb_types, n.c_str());
	switch(kind)
	{
		case R_TYPE_STRUCT:
			return queryR2Struct(n);
		case R_TYPE_ENUM:
			return queryR2Enum(n);
		default:
			return nullptr;
	}
}

Datatype *R2TypeFactory::findById(const string &n, uint8 id)
{
	Datatype *r = TypeFactory::findById(n, id);
	if(r)
		return r;

	std::set<std::string> stackTypes; // to detect recursion
	return queryR2(n, stackTypes);
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
		case R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER:
		{
			if(ctype->identifier.kind == R_PARSE_CTYPE_IDENTIFIER_KIND_UNION)
			{
				if(error)
					*error = "Union types not supported in Decompiler";
				return nullptr;
			}

			Datatype *r = findByName(ctype->identifier.name);
			if(!r)
			{
				if(error)
					*error = "Unknown type identifier " + std::string(ctype->identifier.name);
				return nullptr;
			}
			if(ctype->identifier.kind == R_PARSE_CTYPE_IDENTIFIER_KIND_STRUCT && r->getMetatype() != TYPE_STRUCT)
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of a struct";
				return nullptr;
			}
			if(ctype->identifier.kind == R_PARSE_CTYPE_IDENTIFIER_KIND_ENUM && !r->isEnumType())
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of an enum";
				return nullptr;
			}
			return r;
		}
		case R_PARSE_CTYPE_TYPE_KIND_POINTER:
		{
			Datatype *sub = fromCType(ctype->pointer.type, error);
			if(!sub)
				return nullptr;
			auto space = arch->getDefaultCodeSpace();
			return this->getTypePointer(space->getAddrSize(), sub, space->getWordSize());
		}
		case R_PARSE_CTYPE_TYPE_KIND_ARRAY:
		{
			Datatype *sub = fromCType(ctype->array.type, error);
			if(!sub)
				return nullptr;
			return this->getTypeArray(ctype->array.count, sub);
		}
	}
	return nullptr;
}