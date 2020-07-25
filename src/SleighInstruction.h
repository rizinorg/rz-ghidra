/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHINSTRUCTION_H
#define R2GHIDRA_SLEIGHINSTRUCTION_H

#include <vector>
#include <unordered_set>
#include "architecture.hh"
#include "sleigh_arch.hh"
#include "SleighAsm.h"

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

/**
 * Class for walking pcode templates OpTpl in the correct order
 * Supports walking the tree of an entire SleighInstructionPrototype or just a single ConstructTpl
 *
 */
class OpTplWalker {
	private:
		ConstructState *point = nullptr;		// The current node being visited
		vector<OpTpl *> *oparray = nullptr;		// current array of ops being traversed
		int4 depth;					// Depth of current node within the tree
		int4 breadcrumb[64];			// Path of operands from the root
		int maxsize;				// Maximum number of directives for this point
		int sectionnum;

		void setupPoint() {
			maxsize = 0;
			oparray = nullptr;
			Constructor *ct = point->ct;
			if (ct == nullptr)
				return;
			const ConstructTpl *tpl;
			if (sectionnum < 0) {
				tpl = ct->getTempl();
				if (tpl == nullptr)
					return;
			}
			else
				tpl = ct->getNamedTempl(sectionnum);
			if (tpl == nullptr) {			// Empty named section implies straight list of build directives
				maxsize = ct->getNumOperands();
			}
			else {
				oparray = &const_cast<std::vector<OpTpl *>&>(tpl->getOpvec());
				maxsize = oparray->size();
			}
		}

	public:
		/**
		 * Constructor for walking an entire parse tree
		 * @param root is the root ConstructState of the tree
		 * @param sectionnum is the named section to traverse (or -1 for main section)
		 */
		OpTplWalker(ConstructState *root,int sectionnum) : point(root), sectionnum(sectionnum) {
			// NOTE: breadcrumb array size limits depth of parse
			depth = 0;
			breadcrumb[0] = 0;
			setupPoint();
		}

		/**
		 * Constructor for walking a single template
		 * @param tpl
		 */
		OpTplWalker(ConstructTpl *tpl) {
			depth = 0;
			breadcrumb[0] = 0;
			oparray = &const_cast<std::vector<OpTpl *>&>(tpl->getOpvec());
			maxsize = oparray->size();
		}

		ConstructState *getState() {
			return point;
		}

		bool isState() {
			if (point != nullptr)
				return true;
			return (maxsize > 0);
		}

		/**
		 * While walking the OpTpl's in order, follow a particular BUILD directive into its respective Constructor and ContructTpl
		 * Use popBuild to backtrack
		 * @param buildnum is the operand number of the BUILD directive to follow
		 */
		void pushBuild(int buildnum) {
			point = point->resolve[buildnum];
			depth += 1;
			breadcrumb[depth] = 0;
			setupPoint();
		}

		/**
		 * Move to the parent of the current node
		 */
		void popBuild() {
			if (point == nullptr) {
				maxsize = 0;
				oparray = nullptr;
				return;
			}
			point = point->parent;
			depth -= 1;
			if (point != nullptr)
				setupPoint();
			else {
				maxsize = 0;
				oparray = nullptr;
			}
		}

		int nextOpTpl(OpTpl *(&lastop)) {
			int curind = breadcrumb[depth]++;
			if (curind >= maxsize)
				return -1;
			if (oparray == nullptr)
				// Plus one to avoid overlay when zero appear, which means return truly lastop
				return curind + 1;				// Virtual build directive
			OpTpl *op = (*oparray)[curind];
			if (op->getOpcode() != OpCode::CPUI_MULTIEQUAL) {	// if NOT a build directive
				lastop = op;
				return 0;								// return ordinary OpTpl
			}
			curind = (int)op->getIn(0)->getOffset().getReal();		// Get the operand index from the build directive
			return curind + 1;
		}
};

class SleighParserContext : public ParserContext
{
	private:
		SleighInstruction *prototype = nullptr;

	public:
		SleighParserContext(ContextCache *ccache): ParserContext(ccache) {}
		SleighInstruction *getPrototype() { return prototype; }
		void setPrototype(SleighInstruction *p) { prototype = p; }

		void initialize(int4 maxstate,int4 maxparam,AddrSpace *spc) {
			ParserContext::initialize(maxstate, maxparam, spc);
			base_state = &prototype->rootState;
		}
};

class SleighAsm;

class SleighInstruction
{
	/* Compared to Java version of SleighInstructionPrototype,
	 * Java choose to resolve all the constructors involved in instruction in ctor
	 * and cache all SleighInstructionPrototype.
	 * C++ choose to cache all constructors in Sleigh's contextcache.
	 */
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
			ConstructState *addressnode = nullptr;		// Constructor state containing destination address of flow
			OpTpl *op = nullptr;						// The pcode template producing the flow
			FlowFlags flowFlags = FlowFlags(0);					// flags associated with this flow
		};

		struct FlowSummary {
			int delay = 0;
			bool hasCrossBuilds = false;
			std::vector<FlowRecord *> flowState;
			OpTpl *lastop = nullptr;
		};

		FlowType flowType = FlowType::INVALID;
		int delaySlotByteCnt = 0;
		bool hasCrossBuilds = false;
		std::vector<FlowRecord *> flowStateList;
		std::vector<std::vector<FlowRecord *>> flowStateListNamed;
		SleighAsm *sleigh = nullptr;
		SleighParserContext *protoContext = nullptr;

		FlowFlags gatherFlags(FlowFlags curflags, int secnum);
		void gatherFlows(std::vector<Address> &res, ParserContext *parsecontext, int secnum);
		Address getHandleAddr(FixedHandle &hand, AddrSpace *curSpace);
		void cacheTreeInfo(); // It could be renamed to parse(), but keep original name to ease later update
		static FlowType convertFlowFlags(FlowFlags flags);
		static FlowType flowListToFlowType(std::vector<FlowRecord *> &flowstate);
		static bool handleIsInvalid(FixedHandle &hand);
		static FlowSummary walkTemplates(OpTplWalker &walker);
		static void addExplicitFlow(ConstructState *state, OpTpl *op, FlowFlags flags, FlowSummary &summary);
		void initPCCache() {
			if(sleigh->trans.pccache == nullptr)
				sleigh->trans.pccache = new R2Sleigh::R2DisassemblyCache(sleigh->trans.cache, sleigh->trans.getConstantSpace(), 8, 256);
		}

	public:
		Address baseaddr;
		ConstructState rootState;

		SleighInstruction(SleighAsm *s, Address &addr) : sleigh(s), baseaddr(addr) {
			if(sleigh == nullptr)
				throw LowlevelError("Null pointer in SleighInstruction ctor");

			initPCCache();

			rootState.parent = nullptr; // rootState = new ConstructState(null);

			//protoContext = new SleighParserContext(sleigh->trans.cache, this); // SleighParserContext protoContext = new SleighParserContext(buf, this, context);

			getParserContext(baseaddr, this);

			cacheTreeInfo();
		}

		~SleighInstruction() { if(protoContext) delete protoContext; }

		FlowType getFlowType();
		std::vector<Address> getFlows();
		SleighParserContext *getParserContext(const Address &addr);
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