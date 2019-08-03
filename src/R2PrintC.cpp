#include "R2PrintC.h"
#include "R2Emit.h"
#include "R2Architecture.h"

R2PrintC::R2PrintC(Architecture *g, const string &nm)
	: PrintC(g, nm)
{
	emit = new R2Emit(400);
}

void R2PrintC::emitGotoStatement(const FlowBlock *bl,const FlowBlock *exp_bl, uint4 type)
{
	auto r2emit = dynamic_cast<R2Emit *>(emit);
	if (bl->lastOp())
	{
		r2emit->pushOffset(bl->lastOp()->getAddr());
	}
	PrintC::emitGotoStatement(bl, exp_bl, type);
}

void R2PrintC::emitStatement(const PcodeOp *inst)
{
	stringstream statement_stream;
	Address addr = inst->getAddr();
	auto r2emit = dynamic_cast<R2Emit *>(emit);
	ostream *saved_stream = getOutputStream();
	setOutputStream(&statement_stream);
	r2emit->pushOffset(addr);

	PrintC::emitStatement(inst);

	*saved_stream << statement_stream.str();
	setOutputStream(saved_stream);
	pushStatement(addr, statement_stream.str());
}

void R2PrintC::pushStatement(Address addr, std::string statement)
{
	smap.insert(std::pair<Address, std::string>(addr, statement));
}


vector<vector<Address>> R2PrintC::getOffsets()
{
	auto r2emit = dynamic_cast<R2Emit *>(emit);
	return r2emit->getOffsets();
}
