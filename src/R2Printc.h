
#ifndef R2GHIDRA_R2PRINTC_H
#define R2GHIDRA_R2PRINTC_H

#include "printc.hh"

class R2PrintC : public PrintC
{
	private:
		map<Address, string> smap;
	public:
		map<Address, string> getStatementsMap();
		void pushStatement(Address, std::string);
		R2PrintC(Architecture *g,const string &nm="tagged-c-language");
		void emitBlockBasic(const BlockBasic *bb);
		void emitBlockIf(const BlockIf *bl);
		void emitStatement(const PcodeOp *inst);
};


#endif
