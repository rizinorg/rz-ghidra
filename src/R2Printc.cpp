#include "R2Printc.h"
#include "R2Architecture.h"

R2PrintC::R2PrintC(Architecture *g, const string &nm)
	: PrintC(g, nm)
{
}

void R2PrintC::emitBlockBasic(const BlockBasic *bb)
{
	const PcodeOp *inst;
	bool separator;

	commsorter.setupBlockList(bb);
	emitLabelStatement(bb);	// Print label (for flat prints)
	if (isSet(only_branch))
	{
		inst = bb->lastOp();
		if (inst->isBranch())
			emitExpression(inst);	// Only print branch instruction
	}
	else
	{
		separator = false;
		list<PcodeOp *>::const_iterator iter;
		for(iter=bb->beginOp();iter!=bb->endOp();++iter)
		{
			inst = *iter;
			if (inst->notPrinted()) continue;
			if (inst->isBranch())
			{
				if (isSet(no_branch)) continue;
				// A straight branch is always printed by
				// the block classes
				if (inst->code() == CPUI_BRANCH) continue;
			}
			const Varnode *vn = inst->getOut();
			if ((vn!=(const Varnode *)0)&&(vn->isImplied()))
				continue;
			if (separator) 
			{
				if (isSet(comma_separate))
				{
					emit->print(",");
					emit->spaces(1);
				}
				else
				{
					emitCommentGroup(inst);
					emit->tagLine();
				}
			}
			else if (!isSet(comma_separate))
			{
				emitCommentGroup(inst);
				emit->tagLine();
			}
			emitStatement(inst);
			std::stringstream stream3;
			stream3 << "R2_OFFSET_START" << inst->getAddr().getOffset()<< "R2_OFFSET_STOP";

			emit->print(stream3.str().c_str());
			separator = true;
		}
		// If we are printing flat structure and there
		// is no longer a normal fallthru, print a goto
		if (isSet(flat)&&isSet(nofallthru))
		{
			inst = bb->lastOp();
			emit->tagLine();
			int4 id = emit->beginStatement(inst);
			emit->print("goto",EmitXml::keyword_color);
			emit->spaces(1);
			if (bb->sizeOut()==2)
			{
				if (inst->isFallthruTrue())
					emitLabel(bb->getOut(1));
				else
					emitLabel(bb->getOut(0));
			}
			else
				emitLabel(bb->getOut(0));
			emit->print(";");
			emit->endStatement(id);
		}
		emitCommentGroup((const PcodeOp *)0); // Any remaining comments
	}
}

void R2PrintC::emitBlockIf(const BlockIf *bl)
{
	const PcodeOp *op;

	// if block never prints final branch
	// so no_branch and only_branch don't matter
	// and shouldn't be passed automatically to
	// the subblocks
	pushMod();
	unsetMod(no_branch|only_branch);

	pushMod();
	setMod(no_branch);
	uintb ifBlockAddr;
	if (bl->getBlock(0)->lastOp())
	{
		ifBlockAddr = bl->getBlock(0)->lastOp()->getAddr().getOffset();
	}
	bl->getBlock(0)->emit(this);
	popMod();
	emit->tagLine();
	op = bl->getBlock(0)->lastOp();
	emit->tagOp("if",EmitXml::keyword_color,op);
	emit->spaces(1);
	pushMod();
	setMod(only_branch);
	bl->getBlock(0)->emit(this);
	popMod();
	if (bl->getGotoTarget() != (FlowBlock *)0)
	{
		emit->spaces(1);
		emitGotoStatement(bl->getBlock(0),bl->getGotoTarget(),bl->getGotoType());
		popMod();
		return;
	}

	setMod(no_branch);
	std::stringstream stream3;
	stream3 << " R2_OFFSET_START" << ifBlockAddr<< "R2_OFFSET_STOP";
	emit->print(stream3.str().c_str());
	if (!option_newline_before_opening_brace)
	{
		emit->spaces(1);
	}
	else
	{
		emit->tagLine();
	}
	int4 id = emit->startIndent();
	emit->print("{");
	int4 id1 = emit->beginBlock(bl->getBlock(1));
	bl->getBlock(1)->emit(this);
	emit->endBlock(id1);
	emit->stopIndent(id);
	emit->tagLine();
	emit->print("}");
	if (bl->getSize()==3)
	{
		if (option_newline_before_else)
		{
			emit->tagLine();
		}
		emit->print("else",EmitXml::keyword_color);
		if (option_newline_before_else)
		{
			emit->tagLine();
		}
		else
		{
			emit->spaces(1);
		}
		int4 id = emit->startIndent();
		emit->print("{");
		int4 id2 = emit->beginBlock(bl->getBlock(2));
		bl->getBlock(2)->emit(this);
		emit->endBlock(id2);
		emit->stopIndent(id);
		emit->tagLine();
		emit->print("}");
	}
	popMod();
}

void R2PrintC::emitStatement(const PcodeOp *inst)
{
	stringstream statement_stream;
	Address addr = inst->getAddr();
	int4 id = emit->beginStatement(inst);
	ostream *saved_stream = getOutputStream();
	setOutputStream(&statement_stream);
	emitExpression(inst);
	emit->endStatement(id);
	if (!isSet(comma_separate))
		emit->print(";");
	*saved_stream << statement_stream.str();
	pushStatement(addr, statement_stream.str());
	setOutputStream(saved_stream);
}

void R2PrintC::pushStatement(Address addr, std::string statement)
{
	smap.insert(std::pair<Address, std::string>(addr, statement));
}


map<Address, string> R2PrintC::getStatementsMap()
{
	return smap;
}
