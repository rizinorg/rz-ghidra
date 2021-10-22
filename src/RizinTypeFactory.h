// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RIZINTYPEFACTORY_H
#define RZ_GHIDRA_RIZINTYPEFACTORY_H

#include <type.hh>

typedef struct rz_ast_parser_t RzASTParser;
typedef struct rz_type_t RzType;
typedef struct rz_base_type_t RzBaseType;

class RizinArchitecture;

class RizinTypeFactory : public TypeFactory
{
	public:
		using StackTypes = std::set<std::string>;

	private:
		RizinArchitecture *arch;
		std::set<Datatype *> prototypes; // set of types that have not been created fully yet

		Datatype *addRizinStruct(RzBaseType *type, StackTypes &stack_types, bool prototype);
		Datatype *addRizinEnum(RzBaseType *type);
		Datatype *addRizinTypedef(RzBaseType *type, StackTypes &stack_types);
		Datatype *addRizinAtomicType(RzBaseType *type, StackTypes &stack_types);
		Datatype *queryRizin(const string &n, StackTypes &stack_types, bool prototype);

	protected:
		Datatype *findById(const string &n, uint8 id, int4 sz) override;
		Datatype *findById(const string &n, uint8 id, int4 sz, StackTypes &stack_types, bool prototype);
		using TypeFactory::findByName;
		Datatype *findByName(const string &n, StackTypes &stack_types, bool prototype) { return findById(n, 0, 0, stack_types, prototype); }
		Datatype *fromRzTypeInternal(const RzType *ctype, string *error, StackTypes *stack_types, bool prototype, bool refd);

	public:
		RizinTypeFactory(RizinArchitecture *arch);
		~RizinTypeFactory() override;

		Datatype *fromRzType(const RzType *ctype, string *error = nullptr, StackTypes *stack_types = nullptr);
};

#endif //RZ_GHIDRA_RizinTYPEFACTORY_H
