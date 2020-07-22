/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHINSTRUCTION_H
#define R2GHIDRA_SLEIGHINSTRUCTION_H

#include <vector>
#include <unordered_set>
#include "architecture.hh"
#include "sleigh_arch.hh"

typedef enum 
{
	INVALID,
	CONDITIONAL_COMPUTED_CALL,
	COMPUTED_CALL,
	CONDITIONAL_CALL,
	JUMP_TERMINATOR,
	CONDITIONAL_JUMP,
	COMPUTED_CALL_TERMINATOR,
	CALL_TERMINATOR,
	TERMINATOR,
	CONDITIONAL_COMPUTED_JUMP,
	UNCONDITIONAL_JUMP,
	COMPUTED_JUMP,
	FALL_THROUGH,
	UNCONDITIONAL_CALL,
	CONDITIONAL_TERMINATOR,
} FlowType;

class InstructionPcodeSlg : public PcodeEmit, public PcodeOpBank // Just for calling PcodeOp's private function
{
	private:
		uintm uniq_id = 0;				///< Counter for producing unique id's for each op
		//TypeFactory *types;		///< List of types for this binary

		PcodeOp *newOp(int4 inputs,const Address &pc) { 
			PcodeOp *op = new PcodeOp(inputs,SeqNum(pc,uniq_id++));
  			op->setFlag(PcodeOp::dead);		// Start out life as dead
  			return op;
		}

		Varnode *newVarnode(int4 s,const Address &m,PcodeOp *op) {
			//Datatype *ct = types->getBase(s,TYPE_UNKNOWN);
			Datatype *ct = new Datatype(s, TYPE_UNKNOWN);
			Varnode *vn = new Varnode(s,m,ct);
  			op->setOutput(vn);
  			return vn;
		}

	public:
		std::vector<PcodeOp> oplist;

		//InstructionPcodeSlg(TypeFactory *t) : types(t) {}

		void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override
		{
			PcodeOp *op = newOp(isize,addr);

			if (outvar != nullptr) {
    			Address oaddr(outvar->space,outvar->offset);
				op->setOutput(newVarnode(outvar->size,oaddr,op));
  			} 

			op->setOpcode(opc);

  			for(int4 i = 0; i < isize; ++i) {
    			Address iaddr(vars[i].space,vars[i].offset);
				op->setInput(newVarnode(vars[i].size,iaddr,op),i);
  			}

			oplist.push_back(op);
		}
};

class SleighInstruction : public Sleigh
{
    private:
		enum FlowFlags 
		{
			FLOW_RETURN = 0x01,
			FLOW_CALL_INDIRECT = 0x02,
			FLOW_BRANCH_INDIRECT = 0x04,
			FLOW_CALL = 0x08,
			FLOW_JUMPOUT = 0x10,
			FLOW_NO_FALLTHRU = 0x20,		// op does not fallthru
			FLOW_BRANCH_TO_END = 0x40,
			FLOW_CROSSBUILD = 0x80,
			FLOW_LABEL = 0x100,
		};

		struct FlowRecord
		{
			ConstructState addressnode;		// Constructor state containing destination address of flow
			OpTpl op;						// The pcode template producing the flow
			FlowFlags flowFlags;					// flags associated with this flow		
		};

		std::vector<FlowRecord> flowStateList;
		std::vector<std::vector<FlowRecord>> flowStateListNamed;

		FlowType convertFlowFlags(FlowFlags flags);
		FlowFlags gatherFlags(FlowFlags curflags, int secnum);
		void gatherFlows(std::vector<Address> &res, ParserContext *parsecontext, int secnum);
		Address getHandleAddr(FixedHandle &hand, AddrSpace *curSpace);
		bool handleIsInvalid(FixedHandle &hand);
		// void getInputObjects(PcodeOp pcode, unordered_set<Varnode> inputObjects, unordered_set<Varnode> writtenObjects);
		// void getResultObject(PcodeOp pcode, unordered_set<Varnode> results);
		std::vector<PcodeOp> getPcode(Address &addr);

	public:
		Address baseaddr;

		SleighInstruction(LoadImage *ld,ContextDatabase *c_db) : Sleigh(ld, c_db) {}
		FlowType getFlowType();
		std::vector<Address> getFlows();
		// std::vector<Varnode> getInputObjects();
		// std::vector<Varnode> getResultObjects();
};

class SubParserWalker : public ParserWalker
{
	public:
		SubParserWalker(const ParserContext *c) : ParserWalker(c) {}

		void subTreeState(ConstructState *subtree)
		{
			point = subtree;
			depth = 0;
			breadcrumb[0] = 0;
		}
};

#endif //R2GHIDRA_SLEIGHINSTRUCTION_H