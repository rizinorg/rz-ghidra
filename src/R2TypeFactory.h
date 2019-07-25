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

		Datatype *queryR2Struct(const string &n);
		Datatype *queryR2(const string &n, std::set<std::string> &stackTypes);

	protected:
		Datatype *findById(const string &n, uint8 id) override;

	public:
		R2TypeFactory(R2Architecture *arch);
		~R2TypeFactory() override;

		Datatype *fromCString(const string &str, string *error = nullptr);
		Datatype *fromCType(const RParseCTypeType *ctype, string *error = nullptr);
};

#endif //R2GHIDRA_R2TYPEFACTORY_H
