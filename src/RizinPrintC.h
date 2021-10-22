// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinPRINTC_H
#define RZ_GHIDRA_RizinPRINTC_H

#include <printc.hh>

class RizinPrintC : public PrintC
{
	protected:
		void pushUnnamedLocation(const Address &addr, const Varnode *vn,const PcodeOp *op) override;

	public:
		explicit RizinPrintC(Architecture *g, const string &nm = "c-language");

};

class RizinPrintCCapability : public PrintLanguageCapability
{
	private:
		static RizinPrintCCapability inst;
		RizinPrintCCapability();

	public:
		PrintLanguage *buildLanguage(Architecture *glb) override;
};

#endif //RZ_GHIDRA_RizinPRINTC_H
