#include "SleighInstruction.h"

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

SleighInstruction::FlowFlags SleighInstruction::gatherFlags(FlowFlags curflags, int secnum)
{
	std::vector<FlowRecord> curlist;
	if (secnum < 0)
		curlist = flowStateList;
	else if ((!flowStateListNamed.empty()) && (secnum < flowStateListNamed.size()))
		curlist = flowStateListNamed[secnum];

	if (curlist.empty())
		return curflags;

	for (FlowRecord rec : curlist) {
		if ((rec.flowFlags & FLOW_CROSSBUILD) != 0) {
			ParserContext *pos = obtainContext(baseaddr,ParserContext::pcode);
  			pos->applyCommits();
			SubParserWalker walker(pos);
			walker.subTreeState(&rec.addressnode);

			VarnodeTpl *vn = rec.op.getIn(0);
			AddrSpace *spc = vn->getSpace().fixSpace(walker);
			uintb addr = spc->wrapOffset( vn->getOffset().fix(walker) );
			Address newaddr(spc,addr);
			ParserContext *crosscontext = obtainContext(newaddr,ParserContext::pcode);
			crosscontext->applyCommits();
			int newsecnum = rec.op.getIn(1)->getOffset().getReal();
			SleighInstruction crossproto = crosscontext.getPrototype();
			curflags = crossproto.gatherFlags(curflags, newsecnum);
		}
		else {
			curflags = FlowFlags(curflags & (~(FLOW_CROSSBUILD | FLOW_LABEL | FLOW_NO_FALLTHRU)));
			curflags = FlowFlags(curflags | rec.flowFlags);
		}
	}
	return curflags;
}

void SleighInstruction::gatherFlows(std::vector<Address> &res, ParserContext *parsecontext, int secnum)
{
	std::vector<FlowRecord> curlist;
	if (secnum < 0)
		curlist = flowStateList;
	else if ((!flowStateListNamed.empty()) && (secnum < flowStateListNamed.size()))
		curlist = flowStateListNamed[secnum];

	if (curlist.empty())
		return;

	for (FlowRecord rec : curlist) {
		if ((rec.flowFlags & FLOW_CROSSBUILD) != 0) {
			SubParserWalker walker(parsecontext);
			walker.subTreeState(&rec.addressnode);

			VarnodeTpl *vn = rec.op.getIn(0);
			AddrSpace *spc = vn->getSpace().fixSpace(walker);
			uintb addr = spc->wrapOffset( vn->getOffset().fix(walker) );
			Address newaddr(spc,addr);
			ParserContext *crosscontext = obtainContext(newaddr,ParserContext::pcode);
			crosscontext->applyCommits();
			int newsecnum = rec.op.getIn(1)->getOffset().getReal();
			SleighInstruction crossproto = crosscontext.getPrototype();
			crossproto.gatherFlows(res, crosscontext, newsecnum);
		}
		else if ((rec.flowFlags & (FLOW_JUMPOUT | FLOW_CALL)) != 0) {
			FixedHandle &hand = rec.addressnode.hand;
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

std::vector<PcodeOp> SleighInstruction::getPcode(Address &addr)
{
	InstructionPcodeSlg emit();
	oneInstruction(emit, addr);
	return emit.oplist;
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

	ParserContext *pos = obtainContext(baseaddr,ParserContext::pcode);
  	pos->applyCommits();
	gatherFlows(addresses, pos, -1);

	return addresses;
}