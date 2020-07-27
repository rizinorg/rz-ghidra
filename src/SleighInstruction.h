/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHINSTRUCTION_H
#define R2GHIDRA_SLEIGHINSTRUCTION_H

#include <vector>
#include <unordered_set>
#include "architecture.hh"
#include "sleigh_arch.hh"

class R2Sleigh;
class R2DisassemblyCache;
class SubParserWalker;
class SleighParserContext;
class ExportHelper {
	// Please keep all structures in this class sync with origin!!!
	// A bit hacking here.

	struct ParserWalker { // ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/context.hh
		const ParserContext *const_context;
		const ParserContext *cross_context;
		ConstructState *point;
		int4 depth;
		int4 breadcrumb[32];
	};

	struct DisassemblyCache { // ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.hh
		ContextCache *contextcache;
		AddrSpace *constspace;
		int4 minimumreuse;
		uint4 mask;
		ParserContext **list;
		int4 nextfree;
		ParserContext **hashtable;
	};

	struct Sleigh : public SleighBase { // ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.hh
		LoadImage *loader;
		ContextDatabase *context_db;
		ContextCache *cache;
		mutable DisassemblyCache *discache;
		mutable PcodeCacher pcode_cache;
		void clearForDelete(void);
		ParserContext *obtainContext(const Address &addr,int4 state) const;
		void resolve(ParserContext &pos) const;
		void resolveHandles(ParserContext &pos) const;
		Sleigh(LoadImage *ld,ContextDatabase *c_db);
		virtual ~Sleigh(void);
		void reset(LoadImage *ld,ContextDatabase *c_db);
		virtual void initialize(DocumentStorage &store);
		virtual void registerContext(const string &name,int4 sbit,int4 ebit);
		virtual void setContextDefault(const string &nm,uintm val);
		virtual void allowContextSet(bool val) const;
		virtual int4 instructionLength(const Address &baseaddr) const;
		virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const;
		virtual int4 printAssembly(AssemblyEmit &emit,const Address &baseaddr) const;
	};

	struct ParserContext { // ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/context.hh
		int4 parsestate;
		AddrSpace *const_space;
		uint1 buf[16];
		uintm *context;
		int4 contextsize;
		ContextCache *contcache;
		vector<ContextSet> contextcommit;
		Address addr;
		Address naddr;
		Address calladdr;
		vector<ConstructState> state;
		ConstructState *base_state;
		int4 alloc;
		int4 delayslot;
	};

	public:
		static const ::ParserContext *getConstcontext(SubParserWalker *xxx)  { return ((ExportHelper::ParserWalker *)xxx)->const_context; }
		static ::ParserContext **getList(R2DisassemblyCache *xxx) { return ((ExportHelper::DisassemblyCache *)xxx)->list; }
		static ::ContextCache *getContextcache(R2DisassemblyCache *xxx) { return ((ExportHelper::DisassemblyCache *)xxx)->contextcache; }
		static ::AddrSpace *getConstspace(R2DisassemblyCache *xxx) { return ((ExportHelper::DisassemblyCache *)xxx)->constspace; }
		static ::ContextCache *getCache(R2Sleigh *xxx) { return ((ExportHelper::Sleigh *)xxx)->cache; }
		static ::ConstructState **getBasestate(SleighParserContext *xxx) { return &((ExportHelper::ParserContext *)xxx)->base_state; }
};

typedef enum
{
	INVALID,
	FLOW,
	FALL_THROUGH,
	UNCONDITIONAL_JUMP,
	CONDITIONAL_JUMP,
	UNCONDITIONAL_CALL,
	CONDITIONAL_CALL,
	TERMINATOR,
	COMPUTED_JUMP,
	CONDITIONAL_TERMINATOR,
	COMPUTED_CALL,
	CALL_TERMINATOR,
	COMPUTED_CALL_TERMINATOR,
	CONDITIONAL_CALL_TERMINATOR,
	CONDITIONAL_COMPUTED_CALL,
	CONDITIONAL_COMPUTED_JUMP,
	JUMP_TERMINATOR,
	INDIRECTION,
	CALL_OVERRIDE_UNCONDITIONAL,
	JUMP_OVERRIDE_UNCONDITIONAL,
	CALLOTHER_OVERRIDE_CALL,
	CALLOTHER_OVERRIDE_JUMP,
} FlowType;

static bool flowTypeHasFallthrough(FlowType t) {
	switch (t)
	{
	case FlowType::INVALID:
	case FlowType::FLOW:
	case FlowType::FALL_THROUGH:
	case FlowType::CONDITIONAL_JUMP:
	case FlowType::UNCONDITIONAL_CALL:
	case FlowType::CONDITIONAL_CALL:
	case FlowType::CONDITIONAL_TERMINATOR:
	case FlowType::COMPUTED_CALL:
	case FlowType::CONDITIONAL_COMPUTED_CALL:
	case FlowType::CONDITIONAL_COMPUTED_JUMP:
	case FlowType::CALL_OVERRIDE_UNCONDITIONAL:
	case FlowType::CALLOTHER_OVERRIDE_CALL:
		return true;

	default:
		return false;
	}
}

/**
 * Class for walking pcode templates OpTpl in the correct order
 * Supports walking the tree of an entire SleighInstructionPrototype or just a single ConstructTpl
 *
 */
class OpTplWalker {
	private:
		ConstructState *point = nullptr;		// The current node being visited
		const vector<OpTpl *> *oparray = nullptr;		// current array of ops being traversed
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
				oparray = &tpl->getOpvec();
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
			oparray = &tpl->getOpvec();
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

class SleighInstruction;
class SleighParserContext : public ParserContext
{
	private:
		SleighInstruction *prototype = nullptr;

	public:
		SleighParserContext(ContextCache *ccache): ParserContext(ccache) {}
		SleighInstruction *getPrototype() { return prototype; }
		void setPrototype(SleighInstruction *p);
};

class R2DisassemblyCache : public DisassemblyCache {
	public:
		R2DisassemblyCache(ContextCache *ccache,AddrSpace *cspace,int4 cachesize,int4 windowsize) :
			DisassemblyCache(ccache, cspace, cachesize, windowsize) {
			for(int4 i=0;i<cachesize;++i) {
				delete ExportHelper::getList(this)[i];
				SleighParserContext *pos = new SleighParserContext(ExportHelper::getContextcache(this));
				pos->initialize(75,20,ExportHelper::getConstspace(this));
				ExportHelper::getList(this)[i] = pos;
			}
		}
};

class R2Sleigh : public Sleigh
{
	// To export protected member functions to SleighInstruction
	friend SleighInstruction;

	private:
		mutable R2DisassemblyCache *pccache = nullptr;

	public:
		R2Sleigh(LoadImage *ld,ContextDatabase *c_db) : Sleigh(ld, c_db) {}
		~R2Sleigh() { if(pccache) delete pccache; }
		R2DisassemblyCache *initPCCache();
};


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
		int4 length = 0;
		bool hasCrossBuilds = false;
		std::vector<FlowRecord *> flowStateList;
		std::vector<std::vector<FlowRecord *>> flowStateListNamed;
		R2Sleigh *sleigh = nullptr;
		//SleighParserContext *protoContext = nullptr;

		FlowFlags gatherFlags(FlowFlags curflags, int secnum);
		void gatherFlows(std::vector<Address> &res, ParserContext *parsecontext, int secnum);
		Address getHandleAddr(FixedHandle &hand, AddrSpace *curSpace);
		void cacheTreeInfo(); // It could be renamed to parse(), but keep original name to ease later update
		static FlowType convertFlowFlags(FlowFlags flags);
		static FlowType flowListToFlowType(std::vector<FlowRecord *> &flowstate);
		static bool handleIsInvalid(FixedHandle &hand);
		static FlowSummary walkTemplates(OpTplWalker &walker);
		static void addExplicitFlow(ConstructState *state, OpTpl *op, FlowFlags flags, FlowSummary &summary);

	public:
		Address baseaddr;
		ConstructState rootState;

		SleighParserContext *getParserContext(const Address &addr, SleighInstruction *proto = nullptr);
		FlowType getFlowType();
		std::vector<Address> getFlows();
		static const char *printFlowType(FlowType t);
		int getLength() { return length; }
		Address getFallThrough();
		int getFallThroughOffset();

		SleighInstruction(R2Sleigh *s, Address &addr) : sleigh(s), baseaddr(addr) {
			if(sleigh == nullptr)
				throw LowlevelError("Null pointer in SleighInstruction ctor");

			sleigh->initPCCache();

			rootState.parent = nullptr; // rootState = new ConstructState(null);

			//protoContext = new SleighParserContext(sleigh->trans.cache, this); // SleighParserContext protoContext = new SleighParserContext(buf, this, context);

			getParserContext(baseaddr, this);

			length = rootState.length;

			cacheTreeInfo();
		}

		~SleighInstruction() { //if(protoContext) delete protoContext;
			flowStateListNamed.push_back(flowStateList);
			for(auto outer = flowStateListNamed.begin(); outer != flowStateListNamed.end(); outer++)
				for(auto inner = outer->begin(); inner != outer->end(); inner++)
					delete *inner;
		}
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