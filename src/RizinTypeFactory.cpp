// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinTypeFactory.h"
#include "RizinArchitecture.h"

#include <rz_core.h>
#include <rz_type.h>

#include "RizinUtils.h"

using namespace ghidra;

RizinTypeFactory::RizinTypeFactory(RizinArchitecture *arch)
	: TypeFactory(arch),
	arch(arch)
{
}

RizinTypeFactory::~RizinTypeFactory()
{
}

Datatype *RizinTypeFactory::addRizinStruct(RzBaseType *type, StackTypes &stack_types, bool prototype)
{
	assert(type->kind == RZ_BASE_TYPE_KIND_STRUCT);

	std::vector<TypeField> fields;
	try
	{
		RzCoreLock core(arch->getCore());
		ut64 offset = 0;
		TypeStruct *r = getTypeStruct(type->name);
		if (prototype) {
			prototypes.insert(r);
			return r;
		} else {
			prototypes.erase(r);
		}
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

			TypeField tf = {
				(int4)offset, // id = offset by default
				(int4)offset, // Currently, this is 0 most of the time: member->offset,
				std::string(member->name),
				member_type
			};
			fields.push_back(tf);

			// TODO: right now, we track member offset ourselves
			// which means all structs are assumed to be packed.
			// This should be changed if there is a clear notion of the offset in rizin at some point.
			offset += rz_type_db_get_bitsize(core->analysis->typedb, member->type) / 8;
		});
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

Datatype *RizinTypeFactory::addRizinTypedef(RzBaseType *type, StackTypes &stack_types)
{
	assert(type->kind == RZ_BASE_TYPE_KIND_TYPEDEF);
	if(!type->type)
		return nullptr;
	Datatype *resolved = fromRzTypeInternal(type->type, nullptr, &stack_types, true, false); // use prototype=true to avoid recursion
	if(!resolved)
		return nullptr;
	Datatype *typedefd = getTypedef(resolved, type->name, 0, 0);
	fromRzTypeInternal(type->type, nullptr, &stack_types, false, false); // fully create the type after querying with prototype=true before
	return typedefd;
}

static type_metatype metatypeOfTypeclass(RzTypeTypeclass tc)
{
	switch(tc)
	{
		case RZ_TYPE_TYPECLASS_NUM:
		case RZ_TYPE_TYPECLASS_INTEGRAL:
		case RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED:
			return TYPE_UINT;
		case RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED:
			return TYPE_INT;
		case RZ_TYPE_TYPECLASS_FLOATING:
			return TYPE_FLOAT;
		case RZ_TYPE_TYPECLASS_NONE:
			return TYPE_VOID;
		default:
			return TYPE_UNKNOWN;
	}
}

Datatype *RizinTypeFactory::addRizinAtomicType(RzBaseType *type, StackTypes &stack_types)
{
	assert(type->kind == RZ_BASE_TYPE_KIND_ATOMIC);
	if(!type->name || type->size < 8)
	{
		arch->addWarning(std::string("Invalid atomic type ") + (type->name ? type->name : "(null)"));
		return nullptr;
	}
	RzCoreLock core(arch->getCore());
	type_metatype mt = metatypeOfTypeclass(rz_base_type_typeclass(core->analysis->typedb, type));
	// setCoreType(type->name, type->size / 8, mt, false); // TODO: conditionally enable chartp when supported in rizin
	return getBase(type->size / 8, mt, type->name);
}

Datatype *RizinTypeFactory::queryRizin(const string &n, StackTypes &stack_types, bool prototype)
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
			r = addRizinStruct(type, stack_types, prototype);
			break;
		case RZ_BASE_TYPE_KIND_ENUM:
			r = addRizinEnum(type);
			break;
		case RZ_BASE_TYPE_KIND_TYPEDEF:
			r = addRizinTypedef(type, stack_types);
			break;
		case RZ_BASE_TYPE_KIND_ATOMIC:
			r = addRizinAtomicType(type, stack_types);
			break;
		default:
			break;
	}
beach:
	stack_types.erase(n);
	return r;
}

Datatype *RizinTypeFactory::findById(const string &n, uint8 id, int4 sz, StackTypes &stack_types, bool prototype)
{
	Datatype *r = TypeFactory::findById(n, id, sz);
	if(r && (prototype || prototypes.find(r) == prototypes.end()))
		return r;
	return queryRizin(n, stack_types, prototype);
}

Datatype *RizinTypeFactory::findById(const string &n, uint8 id, int4 sz)
{
	StackTypes stack_types; // to detect recursion
	return findById(n, id, sz, stack_types, false);
}

// prototype means that the type does not have to be completed entirely yet (e.g. struct prototype for typedef)
// refd means that this type is in a pointer of some kind, so we can actually use prototype
// that's because our typedef-likes in ghidra are just clones of the original type, so we must not clone prototypes, only refs.
Datatype *RizinTypeFactory::fromRzTypeInternal(const RzType *ctype, string *error, StackTypes *stack_types, bool prototype, bool refd)
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

			Datatype *r = stack_types ? findByName(ctype->identifier.name, *stack_types, prototype && refd) : findByName(ctype->identifier.name);
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
			Datatype *sub = fromRzTypeInternal(ctype->pointer.type, error, stack_types, prototype, true);
			if(!sub)
				return nullptr;
			auto space = arch->getDefaultCodeSpace();
			return this->getTypePointer(space->getAddrSize(), sub, space->getWordSize());
		}
		case RZ_TYPE_KIND_ARRAY:
		{
			Datatype *sub = fromRzTypeInternal(ctype->array.type, error, stack_types, prototype, refd);
			if(!sub)
				return nullptr;
			return this->getTypeArray(ctype->array.count, sub);
		}
		case RZ_TYPE_KIND_CALLABLE:
		{
			RzCallable *callable = ctype->callable;
			ProtoModel *pm = callable->cc ? arch->protoModelFromRizinCC(callable->cc) : nullptr;
			if(!pm)
			{
				RzCoreLock core(arch->getCore());
				const char *cc = rz_analysis_cc_default(core->analysis);
				if(cc)
					pm = arch->protoModelFromRizinCC(cc);
			}
			if(!pm)
			{
				RzCoreLock core(arch->getCore());
				char *tstr = rz_type_as_string(core->analysis->typedb, ctype);
				if (error) {
					*error = std::string("Failed to get any calling convention for callable ") + tstr;
				}
				rz_mem_free(tstr);
				return nullptr;
			}
			Datatype *outtype = nullptr;
			if(callable->ret)
			{
				outtype = fromRzTypeInternal(callable->ret, error, stack_types, prototype, refd);
				if(!outtype)
					return nullptr;
			}
			std::vector<Datatype *> intypes;
			if(!rz_pvector_foreach_cpp<RzCallableArg>(callable->args, [&](RzCallableArg *arg) {
				if(!arg->type)
					return false;
				Datatype *at = fromRzTypeInternal(arg->type, error, stack_types, prototype, refd);
				if(!at)
					return false;
				intypes.push_back(at);
				return true;
			}))
			{
				return nullptr;
			}
			return this->getTypeCode(pm, outtype, intypes, false); // dotdotdot arg can be used when rizin supports vararg callables
		}
	}
	return nullptr;
}

Datatype *RizinTypeFactory::fromRzType(const RzType *ctype, string *error, StackTypes *stack_types)
{
	return fromRzTypeInternal(ctype, error, stack_types, false, false);
}
