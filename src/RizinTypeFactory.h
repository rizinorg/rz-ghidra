// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinTYPEFACTORY_H
#define RZ_GHIDRA_RizinTYPEFACTORY_H

#include <type.hh>

typedef struct rz_parse_ctype_t RParseCType;
typedef struct rz_parse_ctype_type_t RParseCTypeType;

class RizinArchitecture;

class RizinTypeFactory : public TypeFactory
{
	private:
		RizinArchitecture *arch;
		RParseCType *ctype;

		Datatype *queryRizinStruct(const string &n, std::set<std::string> &stackTypes);
		Datatype *queryRizinEnum(const string &n);
		Datatype *queryRizinTypedef(const string &n, std::set<std::string> &stackTypes);
		Datatype *queryRizin(const string &n, std::set<std::string> &stackTypes);

	protected:
		Datatype *findById(const string &n, uint8 id) override;
		Datatype *findById(const string &n, uint8 id, std::set<std::string> &stackTypes);
		using TypeFactory::findByName;
		Datatype *findByName(const string &n, std::set<std::string> &stackTypes) { return findById(n, 0, stackTypes); }

	public:
		RizinTypeFactory(RizinArchitecture *arch);
		~RizinTypeFactory() override;

		Datatype *fromCString(const string &str, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
		Datatype *fromCType(const RParseCTypeType *ctype, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
};

#endif //RZ_GHIDRA_RizinTYPEFACTORY_H
