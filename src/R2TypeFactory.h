/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2TYPEFACTORY_H
#define R2GHIDRA_R2TYPEFACTORY_H

#include <type.hh>

class R2Architecture;

class R2TypeFactory : public TypeFactory
{
	private:
		R2Architecture *arch;

	protected:
		Datatype *findById(const string &n, uint8 id) override;

	public:
		R2TypeFactory(R2Architecture *arch);
};

#endif //R2GHIDRA_R2TYPEFACTORY_H
