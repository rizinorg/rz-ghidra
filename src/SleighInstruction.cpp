/* radare - LGPL - Copyright 2020 - FXTi */

#include "SleighInstruction.h"

SleighInstructionPrototype *R2Sleigh::getPrototype(SleighInstruction *context)
{
	SleighInstructionPrototype *new_proto = new SleighInstructionPrototype(this, context);
	uint4 hash = new_proto->hashCode;

	if(proto_cache.find(hash) == proto_cache.end())
	{
		new_proto->cacheTreeInfo();
		proto_cache[hash] = new_proto;
	}
	else
	{
		delete new_proto;
		new_proto = proto_cache[hash];
	}

	return new_proto;
}

SleighInstruction *R2Sleigh::getInstruction(Address &addr)
{
	SleighInstruction *inst = nullptr;
	/*
	if(!ins_cache.has(addr.getOffset()))
	{
		*/
		inst = new SleighInstruction(addr);
		inst->proto = getPrototype(inst);
		/*
		ins_cache.put(addr.getOffset(), inst);
	}
	else
		inst = ins_cache.get(addr.getOffset());
	*/

	return inst;
}

void SleighParserContext::setPrototype(SleighInstructionPrototype *p)
{
	prototype = p;
	*getBaseState() = &prototype->rootState;
}

void R2Sleigh::reconstructContext(ParserContext &protoContext)
{
	// R2loader->loadFill(protoContext.getBuffer(), 16, protoContext.getAddr());
	ParserWalkerChange walker(&protoContext);
	protoContext.deallocateState(walker);	// Clear the previous resolve and initialize the walker
	protoContext.setDelaySlot(0);
	// protoContext.loadContext();
	while(walker.isState())
	{
		Constructor *ct = walker.getConstructor();
		if(ct)
		{
			int oper = walker.getOperand();
			int numoper = ct->getNumOperands();
			if(oper == 0)		// Upon first entry to this Constructor
				ct->applyContext(walker); // Apply its context changes
			if(oper < numoper)
			{
				walker.pushOperand(oper);
				continue;
			}
			if(oper >= numoper)
			{
				ConstructTpl *templ = ct->getTempl();
				if (templ && templ->delaySlot() > 0)
					protoContext.setDelaySlot(templ->delaySlot());
			}
		}
		walker.popOperand();
	}
	protoContext.setNaddr(protoContext.getAddr() + protoContext.getLength());	// Update Naddr to pointer after instruction
	protoContext.setParserState(ParserContext::disassembly);
}

SleighParserContext *R2Sleigh::getParserContext(Address &addr, SleighInstructionPrototype *proto)
{
	SleighParserContext *pos = newSleighParserContext(addr, proto);
	reconstructContext(*pos);
	resolveHandles(*pos);

	return pos;
}

SleighParserContext *R2Sleigh::newSleighParserContext(Address &addr, SleighInstructionPrototype *proto)
{
	SleighParserContext *pos = new SleighParserContext(getContextCache());
	pos->initialize(1, 0, getConstantSpace());
	pos->setAddr(addr);
	pos->setPrototype(proto);
	// resolve(*pos); // Resolve ALL the constructors involved in the instruction at this address
	// resolveHandles(*pos); // Resolve handles (assuming Constructors already resolved)
	return pos;
}

void R2Sleigh::resolve(SleighParserContext &pos) const
{				// Resolve ALL the constructors involved in the
				// instruction at this address
	R2loader->loadFill(pos.getBuffer(), 16, pos.getAddr());
	SleighParserWalker walker(&pos);
	pos.deallocateState(walker);	// Clear the previous resolve and initialize the walker
	Constructor *ct, *subct;
	uint4 off;
	int4 oper, numoper;

	pos.setDelaySlot(0);
	walker.setOffset(0);		// Initial offset
	pos.clearCommits();		// Clear any old context commits
	pos.loadContext();		// Get context for current address
	ct = root->resolve(walker);	// Base constructor
	walker.setConstructor(ct);
	ct->applyContext(walker);
	while(walker.isState())
	{
		ct = walker.getConstructor();
		oper = walker.getOperand();
		numoper = ct->getNumOperands();
		while(oper < numoper)
		{
			OperandSymbol *sym = ct->getOperand(oper);
			off = walker.getOffset(sym->getOffsetBase()) + sym->getRelativeOffset();
			walker.allocateOperand(oper); // Here's the only difference from original one in sleigh.cc
			walker.setOffset(off);
			TripleSymbol *tsym = sym->getDefiningSymbol();
			if(tsym)
			{
				subct = tsym->resolve(walker);
				if(subct)
				{
					walker.setConstructor(subct);
					subct->applyContext(walker);
					break;
				}
			}
			walker.setCurrentLength(sym->getMinimumLength());
			walker.popOperand();
			oper += 1;
		}
		if(oper >= numoper)
		{ // Finished processing constructor
			walker.calcCurrentLength(ct->getMinimumLength(),numoper);
			walker.popOperand();
			// Check for use of delayslot
			ConstructTpl *templ = ct->getTempl();
			if(templ && templ->delaySlot() > 0)
				pos.setDelaySlot(templ->delaySlot());
		}
	}
	pos.setNaddr(pos.getAddr() + pos.getLength());	// Update Naddr to pointer after instruction
	pos.setParserState(ParserContext::disassembly);
}

void R2Sleigh::generateLocation(const VarnodeTpl *vntpl, VarnodeData &vn, ParserWalker &walker)
{
	vn.space = vntpl->getSpace().fixSpace(walker);
	vn.size = vntpl->getSize().fix(walker);
	if(vn.space == getConstantSpace())
		vn.offset = vntpl->getOffset().fix(walker) & calc_mask(vn.size);
	else if(vn.space == getUniqueSpace())
	{
		vn.offset = vntpl->getOffset().fix(walker);
		vn.offset |= (walker.getAddr().getOffset() & unique_allocatemask) << 4;
	}
	else
		vn.offset = vn.space->wrapOffset(vntpl->getOffset().fix(walker));
}

void R2Sleigh::generatePointer(const VarnodeTpl *vntpl, VarnodeData &vn, ParserWalker &walker)
{
	const FixedHandle &hand(walker.getFixedHandle(vntpl->getOffset().getHandleIndex()));
	vn.space = hand.offset_space;
	vn.size = hand.offset_size;
	if(vn.space == getConstantSpace())
		vn.offset = hand.offset_offset & calc_mask(vn.size);
	else if(vn.space == getUniqueSpace())
		vn.offset = hand.offset_offset | (walker.getAddr().getOffset() & unique_allocatemask) << 4;
	else
		vn.offset = vn.space->wrapOffset(hand.offset_offset);
}

VarnodeData R2Sleigh::dumpInvar(OpTpl *op, Address &addr)
{
	ParserContext *pos = obtainContext(addr, ParserContext::pcode);
	pos->applyCommits();
	ParserWalker walker(pos);
	walker.baseState();

	VarnodeData res;
	VarnodeTpl *vn = op->getIn(0);

	if(vn->isDynamic(walker))
	{
		generatePointer(vn, res, walker);
		res.size |= 0x80000000;
	}
	else
		generateLocation(vn, res, walker);
	return res;
}

const char *SleighInstructionPrototype::printFlowType(FlowType t)
{
	switch(t)
	{
		case FlowType::INVALID: return "INVALID";
		case FlowType::CONDITIONAL_COMPUTED_CALL: return "CONDITIONAL_COMPUTED_CALL";
		case FlowType::COMPUTED_CALL: return "COMPUTED_CALL";
		case FlowType::CONDITIONAL_CALL: return "CONDITIONAL_CALL";
		case FlowType::JUMP_TERMINATOR: return "JUMP_TERMINATOR";
		case FlowType::CONDITIONAL_JUMP: return "CONDITIONAL_JUMP";
		case FlowType::COMPUTED_CALL_TERMINATOR: return "COMPUTED_CALL_TERMINATOR";
		case FlowType::CALL_TERMINATOR: return "CALL_TERMINATOR";
		case FlowType::TERMINATOR: return "TERMINATOR";
		case FlowType::CONDITIONAL_COMPUTED_JUMP: return "CONDITIONAL_COMPUTED_JUMP";
		case FlowType::UNCONDITIONAL_JUMP: return "UNCONDITIONAL_JUMP";
		case FlowType::COMPUTED_JUMP: return "COMPUTED_JUMP";
		case FlowType::FALL_THROUGH: return "FALL_THROUGH";
		case FlowType::UNCONDITIONAL_CALL: return "UNCONDITIONAL_CALL";
		case FlowType::CONDITIONAL_TERMINATOR: return "CONDITIONAL_TERMINATOR";

		default: throw LowlevelError("printFlowType() out of bound.");
	}
}

FlowType SleighInstructionPrototype::convertFlowFlags(FlowFlags flags)
{
	if((flags & FLOW_LABEL) != 0)
		flags = FlowFlags(flags | FLOW_BRANCH_TO_END);
	flags = FlowFlags(flags & (~(FLOW_CROSSBUILD | FLOW_LABEL)));
	// NOTE: If prototype has cross-build, flow must be determined dynamically
	switch(flags)
	{ // Convert flags to a standard flowtype
		case 0:
		case FLOW_BRANCH_TO_END: return FlowType::FALL_THROUGH;
		case FLOW_CALL: return FlowType::UNCONDITIONAL_CALL;
		case FLOW_CALL | FLOW_NO_FALLTHRU | FLOW_RETURN: return FlowType::CALL_TERMINATOR;
		case FLOW_CALL_INDIRECT | FLOW_NO_FALLTHRU | FLOW_RETURN:
			return FlowType::COMPUTED_CALL_TERMINATOR;
		case FLOW_CALL | FLOW_BRANCH_TO_END:
			return FlowType::CONDITIONAL_CALL; // This could be wrong but doesn't matter much
		case FLOW_CALL | FLOW_NO_FALLTHRU | FLOW_JUMPOUT: return FlowType::COMPUTED_JUMP;
		case FLOW_CALL | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END | FLOW_RETURN:
			return FlowType::UNCONDITIONAL_CALL;
		case FLOW_CALL_INDIRECT: return FlowType::COMPUTED_CALL;
		case FLOW_BRANCH_INDIRECT | FLOW_NO_FALLTHRU: return FlowType::COMPUTED_JUMP;
		case FLOW_BRANCH_INDIRECT | FLOW_BRANCH_TO_END:
		case FLOW_BRANCH_INDIRECT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
		case FLOW_BRANCH_INDIRECT | FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
			return FlowType::CONDITIONAL_COMPUTED_JUMP;
		case FLOW_CALL_INDIRECT | FLOW_BRANCH_TO_END:
		case FLOW_CALL_INDIRECT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
			return FlowType::CONDITIONAL_COMPUTED_CALL;
		case FLOW_RETURN | FLOW_NO_FALLTHRU: return FlowType::TERMINATOR;
		case FLOW_RETURN | FLOW_BRANCH_TO_END:
		case FLOW_RETURN | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
			return FlowType::CONDITIONAL_TERMINATOR;
		case FLOW_JUMPOUT: return FlowType::CONDITIONAL_JUMP;
		case FLOW_JUMPOUT | FLOW_NO_FALLTHRU: return FlowType::UNCONDITIONAL_JUMP;
		case FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END:
			return FlowType::CONDITIONAL_JUMP;
		case FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_RETURN: return FlowType::JUMP_TERMINATOR;
		case FLOW_JUMPOUT | FLOW_NO_FALLTHRU | FLOW_BRANCH_INDIRECT:
			return FlowType::COMPUTED_JUMP; // added for tableswitch in jvm
		case FLOW_BRANCH_INDIRECT | FLOW_NO_FALLTHRU | FLOW_RETURN:
			return FlowType::JUMP_TERMINATOR;
		case FLOW_NO_FALLTHRU: return FlowType::TERMINATOR;
		case FLOW_BRANCH_TO_END | FLOW_JUMPOUT: return FlowType::CONDITIONAL_JUMP;
		case FLOW_NO_FALLTHRU | FLOW_BRANCH_TO_END: return FlowType::FALL_THROUGH;
		default: break;
	}
	return FlowType::INVALID;
}

void SleighInstructionPrototype::addExplicitFlow(ConstructState *state, OpTpl *op, FlowFlags flags,
                                        FlowSummary &summary)
{
	FlowRecord *res = new FlowRecord();
	summary.flowState.push_back(res);
	res->flowFlags = flags;
	res->op = op;
	res->addressnode = nullptr;
	VarnodeTpl *dest = op->getIn(0); // First varnode input contains the destination address
	if((flags & (FLOW_JUMPOUT | FLOW_CALL | FLOW_CROSSBUILD)) == 0)
		return;
	// If the flow is out of the instruction, store the ConstructState so we can easily calculate
	// address
	if(state == nullptr)
		return;
	if((flags & FLOW_CROSSBUILD) != 0)
	{
		res->addressnode = state;
	}
	else if(dest->getOffset().getType() == ConstTpl::handle)
	{
		int oper = dest->getOffset().getHandleIndex();
		Constructor *ct = state->ct;
		OperandSymbol *sym = ct->getOperand(oper);
		if(sym->isCodeAddress())
		{
			res->addressnode = state->resolve[oper];
		}
	}
}

/**
 * Walk the pcode templates in the order they would be emitted.
 * Collect flowFlags FlowRecords
 * @param walker the pcode template walker
 */
SleighInstructionPrototype::FlowSummary SleighInstructionPrototype::walkTemplates(OpTplWalker &walker)
{
	FlowSummary res;
	ConstTpl::const_type destType;
	FlowFlags flags;

	while(walker.isState())
	{
		OpTpl *lastop = nullptr;
		int state = walker.nextOpTpl(lastop);
		if(state == -1)
		{
			walker.popBuild();
			continue;
		}
		else if(state > 0)
		{
			walker.pushBuild(state - 1);
			continue;
		}
		res.lastop = lastop;
		switch(res.lastop->getOpcode())
		{
			case OpCode::CPUI_PTRSUB: // encoded crossbuild directive
				res.hasCrossBuilds = true;
				addExplicitFlow(walker.getState(), res.lastop, FLOW_CROSSBUILD, res);
				break;
			case OpCode::CPUI_BRANCHIND:
				addExplicitFlow(
				    nullptr, res.lastop,
				    FlowFlags(FlowFlags::FLOW_BRANCH_INDIRECT | FlowFlags::FLOW_NO_FALLTHRU), res);
				break;
			case OpCode::CPUI_BRANCH:
				destType = res.lastop->getIn(0)->getOffset().getType();
				if(destType == ConstTpl::j_next)
					flags = FlowFlags::FLOW_BRANCH_TO_END;
				else if(destType == ConstTpl::j_start)
					flags = FlowFlags::FLOW_NO_FALLTHRU;
				else if(destType == ConstTpl::j_relative)
					flags = FlowFlags::FLOW_NO_FALLTHRU;
				else
					flags = FlowFlags(FlowFlags::FLOW_JUMPOUT | FlowFlags::FLOW_NO_FALLTHRU);
				addExplicitFlow(walker.getState(), res.lastop, flags, res);
				break;
			case OpCode::CPUI_CBRANCH:
				destType = res.lastop->getIn(0)->getOffset().getType();
				if(destType == ConstTpl::j_next)
					flags = FlowFlags::FLOW_BRANCH_TO_END;
				else if((destType != ConstTpl::j_start) && (destType != ConstTpl::j_relative))
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
				addExplicitFlow(nullptr, res.lastop,
				                FlowFlags(FlowFlags::FLOW_RETURN | FlowFlags::FLOW_NO_FALLTHRU),
				                res);
				break;
			case OpCode::CPUI_PTRADD: // Encoded label build directive
				addExplicitFlow(nullptr, res.lastop, FlowFlags::FLOW_LABEL, res);
				break;
			case OpCode::CPUI_INDIRECT: // Encode delayslot
				destType = res.lastop->getIn(0)->getOffset().getType();
				if(destType > res.delay)
					res.delay = destType;
				break;
			default: break;
		}
	}
	return res;
}

FlowType SleighInstructionPrototype::flowListToFlowType(std::vector<FlowRecord *> &flowstate)
{
	if(flowstate.empty())
		return FlowType::FALL_THROUGH;
	FlowFlags flags = FlowFlags(0);
	for(FlowRecord *rec: flowstate)
	{
		flags = FlowFlags(flags & (~(FLOW_NO_FALLTHRU | FLOW_CROSSBUILD | FLOW_LABEL)));
		flags = FlowFlags(flags | rec->flowFlags);
	}
	return convertFlowFlags(flags);
}

/**
 * Walk the Constructor tree gathering ConstructStates which are flow destinations (flowStateList)
 * flowFlags and delayslot directives
 */
void SleighInstructionPrototype::cacheTreeInfo()
{
	OpTplWalker walker(&rootState, -1);
	FlowSummary summary = walkTemplates(walker);

	delaySlotByteCnt = summary.delay;
	hasCrossBuilds = summary.hasCrossBuilds;
	if(!summary.flowState.empty())
	{
		flowStateList = summary.flowState;
		flowType = flowListToFlowType(summary.flowState);
	}
	else
	{
		flowType = FlowType::FALL_THROUGH;
	}

	for(uint4 i = 0; i < sleigh->numSections; i++)
	{
		walker = OpTplWalker(&rootState, i);
		summary = walkTemplates(walker);
		flowStateListNamed.push_back(summary.flowState);
	}
}

VarnodeData SleighInstructionPrototype::getIndirectInvar(SleighInstruction *inst)
{
	std::vector<FlowRecord *> curlist = flowStateList;
	for(FlowRecord *rec: curlist)
	{
		if((rec->flowFlags & (FLOW_BRANCH_INDIRECT | FLOW_CALL_INDIRECT)) != 0)
			return sleigh->dumpInvar(rec->op, inst->baseaddr);
	}
	return VarnodeData();
}

SleighInstructionPrototype::FlowFlags SleighInstructionPrototype::gatherFlags(FlowFlags curflags, SleighInstruction *inst, int secnum)
{
	std::vector<FlowRecord *> curlist;
	if(secnum < 0)
		curlist = flowStateList;
	else if((!flowStateListNamed.empty()) && (secnum < flowStateListNamed.size()))
		curlist = flowStateListNamed[secnum];

	if(curlist.empty())
		return curflags;

	SleighParserContext *pos = inst->getParserContext();
	pos->applyCommits();
	pos->clearCommits();

	for(FlowRecord *rec: curlist)
	{
		if((rec->flowFlags & FLOW_CROSSBUILD) != 0)
		{
			SleighParserWalker walker(pos);
			walker.subTreeState(rec->addressnode);

			VarnodeTpl *vn = rec->op->getIn(0);
			AddrSpace *spc = vn->getSpace().fixSpace(walker);
			uintb addr = spc->wrapOffset(vn->getOffset().fix(walker));

			Address newaddr(spc, addr);
			SleighParserContext *crosscontext = inst->getParserContext(newaddr);
			int newsecnum = rec->op->getIn(1)->getOffset().getReal();
			curflags = crosscontext->getPrototype()->gatherFlags(curflags, inst, newsecnum);
			delete crosscontext;
		}
		else
		{
			curflags = FlowFlags(curflags & (~(FLOW_CROSSBUILD | FLOW_LABEL | FLOW_NO_FALLTHRU)));
			curflags = FlowFlags(curflags | rec->flowFlags);
		}
	}

	delete pos;

	return curflags;
}

void SleighInstructionPrototype::gatherFlows(std::vector<Address> &res, SleighInstruction *inst,
                                    int secnum)
{
	std::vector<FlowRecord *> curlist;
	if(secnum < 0)
		curlist = flowStateList;
	else if((!flowStateListNamed.empty()) && (secnum < flowStateListNamed.size()))
		curlist = flowStateListNamed[secnum];

	if(curlist.empty())
		return;

	SleighParserContext *parsecontext = inst->getParserContext();
	parsecontext->applyCommits();
	parsecontext->clearCommits();

	for(FlowRecord *rec: curlist)
	{
		if((rec->flowFlags & FLOW_CROSSBUILD) != 0)
		{
			SleighParserWalker walker(parsecontext);
			walker.subTreeState(rec->addressnode);

			VarnodeTpl *vn = rec->op->getIn(0);
			AddrSpace *spc = vn->getSpace().fixSpace(walker);
			uintb addr = spc->wrapOffset(vn->getOffset().fix(walker));

			Address newaddr(spc, addr);
			SleighParserContext *crosscontext = inst->getParserContext(newaddr);
			int newsecnum = rec->op->getIn(1)->getOffset().getReal();
			crosscontext->getPrototype()->gatherFlows(res, inst, newsecnum);
			delete crosscontext;
		}
		else if((rec->flowFlags & (FLOW_JUMPOUT | FLOW_CALL)) != 0)
		{
			FixedHandle &hand = rec->addressnode->hand;
			if(!handleIsInvalid(hand) && hand.offset_space == nullptr)
			{
				Address addr = getHandleAddr(hand, parsecontext->getAddr().getSpace());
				res.push_back(addr);
			}
		}
	}

	delete parsecontext;
}

Address SleighInstructionPrototype::getHandleAddr(FixedHandle &hand, AddrSpace *curSpace)
{
	if(handleIsInvalid(hand) || hand.space->getType() == spacetype::IPTR_INTERNAL ||
	   hand.offset_space != nullptr)
		return Address();

	Address newaddr(hand.space, hand.space->wrapOffset(hand.offset_offset));

	newaddr.toPhysical();

	// if we are in an address space, translate it
	// if (curSpace.isOverlaySpace()) {
	// newaddr = curSpace.getOverlayAddress(newaddr);
	// }
	return newaddr;
}

bool SleighInstructionPrototype::handleIsInvalid(FixedHandle &hand)
{
	return hand.space == nullptr;
}

FlowType SleighInstructionPrototype::getFlowType(SleighInstruction *inst)
{
	if(!hasCrossBuilds)
		return flowType;

	return convertFlowFlags(gatherFlags(FlowFlags(0), inst, -1));
}

std::vector<Address> SleighInstructionPrototype::getFlows(SleighInstruction *inst)
{
	std::vector<Address> addresses;
	if(flowStateList.empty())
		return addresses;

	gatherFlows(addresses, inst, -1);

	return addresses;
}

Address SleighInstructionPrototype::getFallThrough(SleighInstruction *inst)
{
	if(flowTypeHasFallthrough(flowType))
		return inst->baseaddr + getFallThroughOffset(inst);

	return Address();
}

int SleighInstructionPrototype::getFallThroughOffset(SleighInstruction *inst)
{
	if(delaySlotByteCnt <= 0)
		return getLength();

	int offset = getLength();
	int bytecount = 0;
	do
	{
		Address off_addr = inst->baseaddr + offset;
		SleighInstruction inst(off_addr);

		SleighInstructionPrototype *ins = sleigh->getPrototype(&inst);
		int len = ins->getLength();
		if(!len)
			throw LowlevelError("getFallThroughOffset(): length of current instruction is zero.");
		offset += len;
		bytecount += len;
	} while(bytecount < delaySlotByteCnt);
	return offset;
}

void R2Sleigh::clearCache()
{
	ins_cache.clear();
	for(auto p = proto_cache.begin(); p != proto_cache.end(); ++p)
		delete p->second;
}

FlowType SleighInstruction::getFlowType()
{
	if(!proto)
		throw LowlevelError("getFlowType: proto is not inited.");
	return proto->getFlowType(this);
}

std::vector<Address> SleighInstruction::getFlows()
{
	if(!proto)
		throw LowlevelError("getFlows: proto is not inited.");
	return proto->getFlows(this);
}

SleighParserContext *SleighInstruction::getParserContext(Address &addr)
{
	if(!proto)
		throw LowlevelError("getParserContext: proto is not inited.");
	return proto->getParserContext(addr);
}

SleighParserContext *SleighInstruction::getParserContext()
{
	if(!proto)
		throw LowlevelError("getParserContext: proto is not inited.");
	return proto->getParserContext(baseaddr);
}

Address SleighInstruction::getFallThrough()
{
	if(!proto)
		throw LowlevelError("getFallThrough: proto is not inited.");
	return proto->getFallThrough(this);
}

VarnodeData SleighInstruction::getIndirectInvar()
{
	if(!proto)
		throw LowlevelError("getIndirectInvar: proto is not inited.");
	return proto->getIndirectInvar(this);
}