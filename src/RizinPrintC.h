// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinPRINTC_H
#define RZ_GHIDRA_RizinPRINTC_H

#include <printc.hh>

class RizinPrintC : public ghidra::PrintC
{
	protected:
		void pushUnnamedLocation(const ghidra::Address &addr, const ghidra::Varnode *vn,const ghidra::PcodeOp *op) override;
		std::string genericFunctionName(const ghidra::Address &addr) override;

	public:
		explicit RizinPrintC(ghidra::Architecture *g, const std::string &nm = "c-language");

};

class RizinPrintCCapability : public ghidra::PrintLanguageCapability
{
	private:
		static RizinPrintCCapability inst;
		RizinPrintCCapability();

	public:
		ghidra::PrintLanguage *buildLanguage(ghidra::Architecture *glb) override;
};

#endif //RZ_GHIDRA_RizinPRINTC_H
