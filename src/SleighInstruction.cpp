#include "SleighInstruction.h"

R2DisassemblyCache *R2Sleigh::initPCCache(SleighInstruction *ins) {
	if (pccache == nullptr)
		pccache = new R2DisassemblyCache(ExportHelper::getCache(this), getConstantSpace(), 8, 256);
	return pccache;
}

FlowType SleighInstruction::convertFlowFlags(FlowFlags flags)
{
		if ((flags & FLOW_LABEL) != 0)
			flags = FlowFlags(flags | FLOW_BRANCH_TO_END);
		flags = FlowFlags(flags & (~(FLOW_CROSSBUILD | FLOW_LABEL)));
		// NOTE: If prototype has cross-build, flow must be determined dynamically
		switch (flags) 
		{ // Convert flags to a standard flowtype
			case 0:
			case FLOW_BRANCH_TO_END:
				return FlowType::FALL_THROUGH;
			case FLOW_CALL:
				return FlowType::UNCONDITIONAL_CALL;
			case FLOW_CALL | FLOW_NO_FALLTHRU | FLOW_RETURN:
				return FlowType::CALL_TERMINATOR;
			case FLOW_CALL_INDIRECT | FLOW_NO_FALLTHRU | FLOW_RETURN:
				return FlowType::COMPUTED_CALL_TERMINATOR;
			case FLOW_CALL | FLOW_BRANCH_TO_END:
				return FlowType::CONDITIONAL_CALL; // This could be wrong but doesn't matter much
			case FLOW_CALL | FLOW_NO_FALLTHRU | FLOW_JUMPOUT:
				return FlowType::COMPUTED_JUMP;
			case FLOW_CALL | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END | FLOW_RETURN:
				return FlowType::UNCONDITIONAL_CALL;
			case FLOW_CALL_INDIRECT:
				return FlowType::COMPUTED_CALL;
			case FLOW_BRANCH_INDIRECT | FLOW_NO_FALLTHRU:
				return FlowType::COMPUTED_JUMP;
			case FLOW_BRANCH_INDIRECT | FLOW_BRANCH_TO_END:
			case FLOW_BRANCH_INDIRECT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
			case FLOW_BRANCH_INDIRECT | FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
				return FlowType::CONDITIONAL_COMPUTED_JUMP;
			case FLOW_CALL_INDIRECT | FLOW_BRANCH_TO_END:
			case FLOW_CALL_INDIRECT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
				return FlowType::CONDITIONAL_COMPUTED_CALL;
			case FLOW_RETURN | FLOW_NO_FALLTHRU:
				return FlowType::TERMINATOR;
			case FLOW_RETURN | FLOW_BRANCH_TO_END:
			case FLOW_RETURN | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
				return FlowType::CONDITIONAL_TERMINATOR;
			case FLOW_JUMPOUT:
				return FlowType::CONDITIONAL_JUMP;
			case FLOW_JUMPOUT | FLOW_NO_FALLTHRU:
				return FlowType::UNCONDITIONAL_JUMP;
			case FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
				return FlowType::CONDITIONAL_JUMP;
			case FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_RETURN:
				return FlowType::JUMP_TERMINATOR;
			case FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_BRANCH_INDIRECT:
				return FlowType::COMPUTED_JUMP; //added for tableswitch in jvm
			case FLOW_BRANCH_INDIRECT | FLOW_NO_FALLTHRU | FLOW_RETURN:
				return FlowType::JUMP_TERMINATOR;
			case FLOW_NO_FALLTHRU:
				return FlowType::TERMINATOR;
			case FLOW_BRANCH_TO_END | FLOW_JUMPOUT:
				return FlowType::CONDITIONAL_JUMP;
			case FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
				return FlowType::FALL_THROUGH;
			default:
				break;
		}
		return FlowType::INVALID;
}

 void SleighInstruction::addExplicitFlow(ConstructState *state, OpTpl *op, FlowFlags flags, FlowSummary &summary) {
	FlowRecord *res = new FlowRecord();
	summary.flowState.push_back(res);
	res->flowFlags = flags;
	res->op = op;
	res->addressnode = nullptr;
	VarnodeTpl *dest = op->getIn(0);		// First varnode input contains the destination address
	if ((flags & (FLOW_JUMPOUT | FLOW_CALL | FLOW_CROSSBUILD)) == 0)
		return;
	// If the flow is out of the instruction, store the ConstructState so we can easily calculate address
	if (state == nullptr)
		return;
	if ((flags & FLOW_CROSSBUILD) != 0) {
		res->addressnode = state;
	}
	else if (dest->getOffset().getType() == ConstTpl::handle) {
		int oper = dest->getOffset().getHandleIndex();
		Constructor *ct = state->ct;
		OperandSymbol *sym = ct->getOperand(oper);
		if (sym->isCodeAddress()) {
			res->addressnode = state->resolve[oper];
		}
	}
}

/**
 * Walk the pcode templates in the order they would be emitted.
 * Collect flowFlags FlowRecords
 * @param walker the pcode template walker
 */
SleighInstruction::FlowSummary SleighInstruction::walkTemplates(OpTplWalker &walker)
{
	FlowSummary res;
	ConstTpl::const_type destType;
	FlowFlags flags;

	while (walker.isState()) {
		OpTpl *lastop = nullptr;
		int state = walker.nextOpTpl(lastop);
		if (state == -1) {
			walker.popBuild();
			continue;
		}
		else if (state > 0) {
			walker.pushBuild(state - 1);
			continue;
		}
		res.lastop = lastop;
		switch (res.lastop->getOpcode()) {
			case OpCode::CPUI_PTRSUB:			// encoded crossbuild directive
				res.hasCrossBuilds = true;
				addExplicitFlow(walker.getState(), res.lastop, FLOW_CROSSBUILD, res);
				break;
			case OpCode::CPUI_BRANCHIND:
				addExplicitFlow(nullptr, res.lastop, FlowFlags(FlowFlags::FLOW_BRANCH_INDIRECT | FlowFlags::FLOW_NO_FALLTHRU), res);
				break;
			case OpCode::CPUI_BRANCH:
				destType = res.lastop->getIn(0)->getOffset().getType();
				if (destType == ConstTpl::j_next)
					flags = FlowFlags::FLOW_BRANCH_TO_END;
				else if (destType == ConstTpl::j_start)
					flags = FlowFlags::FLOW_NO_FALLTHRU;
				else if (destType == ConstTpl::j_relative)
					flags = FlowFlags::FLOW_NO_FALLTHRU;
				else
					flags = FlowFlags(FlowFlags::FLOW_JUMPOUT | FlowFlags::FLOW_NO_FALLTHRU);
				addExplicitFlow(walker.getState(), res.lastop, flags, res);
				break;
			case OpCode::CPUI_CBRANCH:
				destType = res.lastop->getIn(0)->getOffset().getType();
				if (destType == ConstTpl::j_next)
					flags = FlowFlags::FLOW_BRANCH_TO_END;
				else if ((destType != ConstTpl::j_start) && (destType != ConstTpl::j_relative))
					flags = FlowFlags::FLOW_JUMPOUT;
				else
					flags = FlowFlags(0);
				addExplicitFlow(walker.getState(), res.lastop, flags, res);
				break;
			case OpCode::CPUI_CALL:
				addExplicitFlow(walker.getState(), res.lastop, FlowFlags::FLOW_CALL, res);
				break;
			case OpCode::CPUI_CALLIND:
				addExplicitFlow(nullptr, res.lastop, FlowFlags::FLOW_CALL_INDIRECT, res);
				break;
			case OpCode::CPUI_RETURN:
				addExplicitFlow(nullptr, res.lastop, FlowFlags(FlowFlags::FLOW_RETURN | FlowFlags::FLOW_NO_FALLTHRU), res);
				break;
			case OpCode::CPUI_PTRADD:			// Encoded label build directive
				addExplicitFlow(nullptr, res.lastop, FlowFlags::FLOW_LABEL, res);
				break;
			case OpCode::CPUI_INDIRECT:			// Encode delayslot
				destType = res.lastop->getIn(0)->getOffset().getType();
				if (destType > res.delay)
					res.delay = destType;
			default:
				break;
		}
	}
	return res;
}

FlowType SleighInstruction::flowListToFlowType(std::vector<FlowRecord *> &flowstate) {
	if (flowstate.empty())
		return FlowType::FALL_THROUGH;
	FlowFlags flags = FlowFlags(0);
	for (FlowRecord *rec : flowstate) {
		flags = FlowFlags(flags & (~(FLOW_NO_FALLTHRU | FLOW_CROSSBUILD | FLOW_LABEL)));
		flags = FlowFlags(flags | rec->flowFlags);
	}
	return convertFlowFlags(flags);
}

/**
 * Walk the Constructor tree gathering ConstructStates which are flow destinations (flowStateList)
 * flowFlags and delayslot directives
 */
void SleighInstruction::cacheTreeInfo()
{
	OpTplWalker walker(&rootState, -1);
	FlowSummary summary = walkTemplates(walker);

	delaySlotByteCnt = summary.delay;
	hasCrossBuilds = summary.hasCrossBuilds;
	if (!summary.flowState.empty()) {
		flowStateList = summary.flowState;
		flowType = flowListToFlowType(summary.flowState);
	} else {
		flowType = FlowType::FALL_THROUGH;
	}

	for (uint4 i = 0; i < sleigh->numSections; i++) {
		walker = OpTplWalker(&rootState, i);
		summary = walkTemplates(walker);
		flowStateListNamed.push_back(summary.flowState);
	}
}

SleighInstruction::FlowFlags SleighInstruction::gatherFlags(FlowFlags curflags, int secnum)
{
	std::vector<FlowRecord *> curlist;
	if (secnum < 0)
		curlist = flowStateList;
	else if ((!flowStateListNamed.empty()) && (secnum < flowStateListNamed.size()))
		curlist = flowStateListNamed[secnum];

	if (curlist.empty())
		return curflags;

	for (FlowRecord *rec : curlist) {
		if ((rec->flowFlags & FLOW_CROSSBUILD) != 0) {
			SleighParserContext *pos = getParserContext(baseaddr, this);
  			pos->applyCommits();
			SubParserWalker walker(pos);
			walker.subTreeState(rec->addressnode);

			VarnodeTpl *vn = rec->op->getIn(0);
			AddrSpace *spc = vn->getSpace().fixSpace(walker);
			uintb addr = spc->wrapOffset( vn->getOffset().fix(walker) );
			Address newaddr(spc,addr);
			SleighParserContext *crosscontext = getParserContext(newaddr);
			crosscontext->applyCommits();
			int newsecnum = rec->op->getIn(1)->getOffset().getReal();
			SleighInstruction *crossproto = crosscontext->getPrototype();
			curflags = crossproto->gatherFlags(curflags, newsecnum);
		}
		else {
			curflags = FlowFlags(curflags & (~(FLOW_CROSSBUILD | FLOW_LABEL | FLOW_NO_FALLTHRU)));
			curflags = FlowFlags(curflags | rec->flowFlags);
		}
	}
	return curflags;
}

void SleighInstruction::gatherFlows(std::vector<Address> &res, ParserContext *parsecontext, int secnum)
{
	std::vector<FlowRecord *> curlist;
	if (secnum < 0)
		curlist = flowStateList;
	else if ((!flowStateListNamed.empty()) && (secnum < flowStateListNamed.size()))
		curlist = flowStateListNamed[secnum];

	if (curlist.empty())
		return;

	for (FlowRecord *rec : curlist) {
		if ((rec->flowFlags & FLOW_CROSSBUILD) != 0) {
			SubParserWalker walker(parsecontext);
			walker.subTreeState(rec->addressnode);

			VarnodeTpl *vn = rec->op->getIn(0);
			AddrSpace *spc = vn->getSpace().fixSpace(walker);
			uintb addr = spc->wrapOffset( vn->getOffset().fix(walker) );
			Address newaddr(spc,addr);
			SleighParserContext *crosscontext = getParserContext(newaddr);
			crosscontext->applyCommits();
			int newsecnum = rec->op->getIn(1)->getOffset().getReal();
			SleighInstruction *crossproto = crosscontext->getPrototype();
			crossproto->gatherFlows(res, crosscontext, newsecnum);
		}
		else if ((rec->flowFlags & (FLOW_JUMPOUT | FLOW_CALL)) != 0) {
			FixedHandle &hand = rec->addressnode->hand;
			if (!handleIsInvalid(hand) && hand.offset_space == nullptr) {
				Address addr = getHandleAddr(hand, parsecontext->getAddr().getSpace());
				res.push_back(addr);
			}
		}
	}
}

Address SleighInstruction::getHandleAddr(FixedHandle &hand, AddrSpace *curSpace)
{
	if (handleIsInvalid(hand) || hand.space->getType() == spacetype::IPTR_INTERNAL || hand.offset_space != nullptr)
		return Address();

	Address newaddr(hand.space, hand.space->wrapOffset(hand.offset_offset));

	newaddr.toPhysical();

	// if we are in an address space, translate it
	// if (curSpace.isOverlaySpace()) {
		// newaddr = curSpace.getOverlayAddress(newaddr);
	// }
	return newaddr;
}

bool SleighInstruction::handleIsInvalid(FixedHandle &hand)
{
	return hand.space == nullptr;
}

FlowType SleighInstruction::getFlowType()
{
	if (!hasCrossBuilds)
		return flowType;

	return convertFlowFlags(gatherFlags(FlowFlags(0), -1));
}

std::vector<Address> SleighInstruction::getFlows()
{
	std::vector<Address> addresses;
	if (flowStateList.empty())
		return addresses;

	SleighParserContext *pos = getParserContext(baseaddr, this);
  	pos->applyCommits();
	gatherFlows(addresses, pos, -1);

	return addresses;
}

SleighParserContext *SleighInstruction::getParserContext(const Address &addr, SleighInstruction *proto) {
	SleighParserContext *pos = (SleighParserContext *)sleigh->pccache->getParserContext(addr);

	if(proto != nullptr)
		pos->setPrototype(proto);

	if (pos->getParserState() == ParserContext::uninitialized) {
		sleigh->resolve(*pos);
		sleigh->resolveHandles(*pos);
	}

	return pos;
}