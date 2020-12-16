// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RZPRINTC_H
#define RZ_GHIDRA_RZPRINTC_H

#include <printc.hh>

class RzPrintC : public PrintC
{
	protected:
		void pushUnnamedLocation(const Address &addr, const Varnode *vn,const PcodeOp *op) override;

	public:
		explicit RzPrintC(Architecture *g, const string &nm = "c-language");

};

class RzPrintCCapability : public PrintLanguageCapability
{
	private:
		static RzPrintCCapability inst;
		RzPrintCCapability();

	public:
		PrintLanguage *buildLanguage(Architecture *glb) override;
};

#endif //RZ_GHIDRA_RZPRINTC_H
