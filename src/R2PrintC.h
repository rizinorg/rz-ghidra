// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_R2PRINTC_H
#define RZ_GHIDRA_R2PRINTC_H

#include <printc.hh>

class R2PrintC : public PrintC
{
	protected:
		void pushUnnamedLocation(const Address &addr, const Varnode *vn,const PcodeOp *op) override;

	public:
		explicit R2PrintC(Architecture *g, const string &nm = "c-language");

};

class R2PrintCCapability : public PrintLanguageCapability
{
	private:
		static R2PrintCCapability inst;
		R2PrintCCapability();

	public:
		PrintLanguage *buildLanguage(Architecture *glb) override;
};

#endif //RZ_GHIDRA_R2PRINTC_H
