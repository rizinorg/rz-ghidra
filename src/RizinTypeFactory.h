// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RIZINTYPEFACTORY_H
#define RZ_GHIDRA_RIZINTYPEFACTORY_H

#include <type.hh>

typedef struct rz_ast_parser_t RzASTParser;
typedef struct rz_type_t RzType;
typedef struct rz_base_type_t RzBaseType;

class RizinArchitecture;

class RizinTypeFactory : public ghidra::TypeFactory
{
	public:
		using StackTypes = std::set<std::string>;

	private:
		RizinArchitecture *arch;
		std::set<ghidra::Datatype *> prototypes; // set of types that have not been created fully yet

		ghidra::Datatype *addRizinStruct(RzBaseType *type, StackTypes &stack_types, bool prototype);
		ghidra::Datatype *addRizinEnum(RzBaseType *type);
		ghidra::Datatype *addRizinTypedef(RzBaseType *type, StackTypes &stack_types);
		ghidra::Datatype *addRizinAtomicType(RzBaseType *type, StackTypes &stack_types);
		ghidra::Datatype *queryRizin(const std::string &n, StackTypes &stack_types, bool prototype);

	protected:
		ghidra::Datatype *findById(const std::string &n, ghidra::uint8 id, ghidra::int4 sz) override;
		ghidra::Datatype *findById(const std::string &n, ghidra::uint8 id, ghidra::int4 sz, StackTypes &stack_types, bool prototype);
		using TypeFactory::findByName;
		ghidra::Datatype *findByName(const std::string &n, StackTypes &stack_types, bool prototype) { return findById(n, 0, 0, stack_types, prototype); }
		ghidra::Datatype *fromRzTypeInternal(const RzType *ctype, std::string *error, StackTypes *stack_types, bool prototype, bool refd);

	public:
		RizinTypeFactory(RizinArchitecture *arch);
		~RizinTypeFactory() override;

		ghidra::Datatype *fromRzType(const RzType *ctype, std::string *error = nullptr, StackTypes *stack_types = nullptr);
};

#endif //RZ_GHIDRA_RizinTYPEFACTORY_H
