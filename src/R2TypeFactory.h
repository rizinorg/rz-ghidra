/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2TYPEFACTORY_H
#define R2GHIDRA_R2TYPEFACTORY_H

#include <type.hh>

typedef struct r_parse_ctype_t RParseCType;
typedef struct r_parse_ctype_type_t RParseCTypeType;

class R2Architecture;

class R2TypeFactory : public TypeFactory
{
	private:
		R2Architecture *arch;
		RParseCType *ctype;

		Datatype *queryR2Struct(const string &n, std::set<std::string> &stackTypes);
		Datatype *queryR2Enum(const string &n);
		Datatype *queryR2Typedef(const string &n, std::set<std::string> &stackTypes);
		Datatype *queryR2(const string &n, std::set<std::string> &stackTypes);

	protected:
		Datatype *findById(const string &n, uint8 id) override;
		Datatype *findById(const string &n, uint8 id, std::set<std::string> &stackTypes);
		using TypeFactory::findByName;
		Datatype *findByName(const string &n, std::set<std::string> &stackTypes) { return findById(n, 0, stackTypes); }

	public:
		R2TypeFactory(R2Architecture *arch);
		~R2TypeFactory() override;

		Datatype *fromCString(const string &str, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
		Datatype *fromCType(const RParseCTypeType *ctype, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
};

#endif //R2GHIDRA_R2TYPEFACTORY_H
