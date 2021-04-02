// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinTYPEFACTORY_H
#define RZ_GHIDRA_RizinTYPEFACTORY_H

#include <type.hh>

typedef struct rz_type_ctype_t RTypeCType;
typedef struct rz_type_ctype_type_t RTypeCTypeType;
typedef struct rz_base_type_t RzBaseType;

class RizinArchitecture;

class RizinTypeFactory : public TypeFactory
{
	private:
		RizinArchitecture *arch;
		RTypeCType *ctype;

		Datatype *addRizinStruct(RzBaseType *type, std::set<std::string> &stack_types);
		Datatype *addRizinEnum(RzBaseType *type);
		Datatype *addRizinTypedef(RzBaseType *type, std::set<std::string> &stack_types);
		Datatype *queryRizin(const string &n, std::set<std::string> &stack_types);

	protected:
		Datatype *findById(const string &n, uint8 id) override;
		Datatype *findById(const string &n, uint8 id, std::set<std::string> &stackTypes);
		using TypeFactory::findByName;
		Datatype *findByName(const string &n, std::set<std::string> &stackTypes) { return findById(n, 0, stackTypes); }

	public:
		RizinTypeFactory(RizinArchitecture *arch);
		~RizinTypeFactory() override;

		Datatype *fromCString(const string &str, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
		Datatype *fromCType(const RTypeCTypeType *ctype, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
};

#endif //RZ_GHIDRA_RizinTYPEFACTORY_H
