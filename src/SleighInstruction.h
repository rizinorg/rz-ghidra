/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHINSTRUCTION_H
#define R2GHIDRA_SLEIGHINSTRUCTION_H

#include <vector>
#include <unordered_set>
#include "architecture.hh"
#include "sleigh_arch.hh"
#include "crc32.hh"
#include <unordered_map>
#include <list>

/**
 * There is still room for optimization, Now SleighInstruction
 * is actually SleighInstructionPrototype in JAVA codebase.
 * But changes to per-instruction implementation.
 * In JAVA codebase, SleighInstructionPrototype is Constructor
 * pattern of one kind of instructions. And concrete flow destination
 * address will be resolved on actual buffer of specified instruction.
 * That's why JAVA codebase cache SleighInstructionPrototype in SleighLanguage.
 * Multiple InstructionContext will be mapped to one single cache prototype,
 * which will save time and space of collecting Constructors.
 * But to implement that in C++ codebase, you will have to create something
 * like InstructionContext and move necessary status and API to that.
 */

template<typename K, typename V>
class LRUCache
{
private:
	std::list<std::pair<K, V>> item_list;
	std::unordered_map<K, decltype(item_list.begin())> item_map;
	const size_t cache_size = 4096; // This takes ~80MB memory space.

	void clean()
	{
		while(item_map.size() > cache_size)
		{
			auto last_it = item_list.back();
			delete last_it.second;
			item_map.erase(last_it.first);
			item_list.pop_back();
		}
	};

public:
	LRUCache() = default;

	~LRUCache() { clear(); }

	void clear()
	{
		for(auto iter = item_list.begin(); iter != item_list.end(); ++iter)
			delete iter->second;
		item_list.clear();
		item_map.clear();
	}

	void put(const K &key, const V &val)
	{
		auto it = item_map.find(key);
		if(it != item_map.end())
		{
			item_list.erase(it->second);
			item_map.erase(it);
		}
		item_list.push_front(make_pair(key, val));
		item_map.insert(make_pair(key, item_list.begin()));
		clean();
	};

	bool has(const K &key) { return item_map.find(key) != item_map.end(); };

	V get(const K &key)
	{
		auto it = item_map.find(key);
		item_list.splice(item_list.begin(), item_list, it->second);
		return it->second->second;
	};
};

enum FlowType
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
};

static bool flowTypeHasFallthrough(FlowType t)
{
	switch(t)
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
		case FlowType::CALLOTHER_OVERRIDE_CALL: return true;

		default: return false;
	}
}

static uint4 hashConstructState(ConstructState *cs, uint4 hashCode)
{
	if(cs->ct == nullptr)
		return hashCode;

	uint4 id = cs->ct->getId();
	hashCode = crc_update(hashCode, id >> 8);
	hashCode = crc_update(hashCode, id);

	for(ConstructState *p: cs->resolve)
		if(p != nullptr)
			hashCode = hashConstructState(p, hashCode);

	return hashCode;
}

/**
 * Class for walking pcode templates OpTpl in the correct order
 * Supports walking the tree of an entire SleighInstructionPrototype or just a single ConstructTpl
 *
 */
class OpTplWalker
{
private:
	ConstructState *point = nullptr;          // The current node being visited
	const vector<OpTpl *> *oparray = nullptr; // current array of ops being traversed
	int4 depth;                               // Depth of current node within the tree
	int4 breadcrumb[64];                      // Path of operands from the root
	int maxsize;                              // Maximum number of directives for this point
	int sectionnum;

	void setupPoint()
	{
		maxsize = 0;
		oparray = nullptr;
		Constructor *ct = point->ct;
		if(ct == nullptr)
			return;
		const ConstructTpl *tpl;
		if(sectionnum < 0)
		{
			tpl = ct->getTempl();
			if(tpl == nullptr)
				return;
		}
		else
			tpl = ct->getNamedTempl(sectionnum);
		if(tpl == nullptr)
		{ // Empty named section implies straight list of build directives
			maxsize = ct->getNumOperands();
		}
		else
		{
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
	OpTplWalker(ConstructState *root, int sectionnum): point(root), sectionnum(sectionnum)
	{
		// NOTE: breadcrumb array size limits depth of parse
		depth = 0;
		breadcrumb[0] = 0;
		setupPoint();
	}

	/**
	 * Constructor for walking a single template
	 * @param tpl
	 */
	OpTplWalker(ConstructTpl *tpl)
	{
		depth = 0;
		breadcrumb[0] = 0;
		oparray = &tpl->getOpvec();
		maxsize = oparray->size();
	}

	ConstructState *getState() { return point; }

	bool isState()
	{
		if(point != nullptr)
			return true;
		return (maxsize > 0);
	}

	/**
	 * While walking the OpTpl's in order, follow a particular BUILD directive into its respective
	 * Constructor and ContructTpl Use popBuild to backtrack
	 * @param buildnum is the operand number of the BUILD directive to follow
	 */
	void pushBuild(int buildnum)
	{
		point = point->resolve[buildnum];
		depth += 1;
		breadcrumb[depth] = 0;
		setupPoint();
	}

	/**
	 * Move to the parent of the current node
	 */
	void popBuild()
	{
		if(point == nullptr)
		{
			maxsize = 0;
			oparray = nullptr;
			return;
		}
		point = point->parent;
		depth -= 1;
		if(point != nullptr)
			setupPoint();
		else
		{
			maxsize = 0;
			oparray = nullptr;
		}
	}

	int nextOpTpl(OpTpl *(&lastop))
	{
		int curind = breadcrumb[depth]++;
		if(curind >= maxsize)
			return -1;
		if(oparray == nullptr)
			// Plus one to avoid overlay when zero appear, which means return truly lastop
			return curind + 1; // Virtual build directive
		OpTpl *op = (*oparray)[curind];
		if(op->getOpcode() != OpCode::CPUI_MULTIEQUAL)
		{ // if NOT a build directive
			lastop = op;
			return 0; // return ordinary OpTpl
		}
		curind = (int)op->getIn(0)
		             ->getOffset()
		             .getReal(); // Get the operand index from the build directive
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
	void setPrototype(SleighInstruction *p, int4 maxparam);
};

class SleighInstruction;
class R2Sleigh : public Sleigh
{
	// To export protected member functions to SleighInstruction
	friend SleighInstruction;

private:
	mutable LRUCache<uintm, SleighInstruction *> ins_cache;

	void generateLocation(const VarnodeTpl *vntpl, VarnodeData &vn, ParserWalker &walker);
	void generatePointer(const VarnodeTpl *vntpl, VarnodeData &vn, ParserWalker &walker);

public:
	R2Sleigh(LoadImage *ld, ContextDatabase *c_db): Sleigh(ld, c_db) {}
	~R2Sleigh() { clearCache(); }

	SleighParserContext *getParserContext(SleighInstruction *proto);

	SleighInstruction *getInstruction(Address &addr);

	VarnodeData dumpInvar(OpTpl *op, Address &addr);

	void clearCache() { ins_cache.clear(); }

	ParserContext *getContext(const Address &addr,int4 state) const
	{
		return obtainContext(addr, state);
	}
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
		FLOW_NO_FALLTHRU = 0x20, // op does not fallthru
		FLOW_BRANCH_TO_END = 0x40,
		FLOW_CROSSBUILD = 0x80,
		FLOW_LABEL = 0x100,
	};

	struct FlowRecord
	{
		ConstructState *addressnode =
		    nullptr;         // Constructor state containing destination address of flow
		OpTpl *op = nullptr; // The pcode template producing the flow
		FlowFlags flowFlags = FlowFlags(0); // flags associated with this flow
	};

	struct FlowSummary
	{
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
	SleighParserContext *protoContext = nullptr;

	FlowFlags gatherFlags(FlowFlags curflags, int secnum);
	void gatherFlows(std::vector<Address> &res, ParserContext *parsecontext, int secnum);
	Address getHandleAddr(FixedHandle &hand, AddrSpace *curSpace);
	void cacheTreeInfo(); // It could be renamed to parse(), but keep original name to ease later
	                      // update
	static FlowType convertFlowFlags(FlowFlags flags);
	static FlowType flowListToFlowType(std::vector<FlowRecord *> &flowstate);
	static bool handleIsInvalid(FixedHandle &hand);
	static FlowSummary walkTemplates(OpTplWalker &walker);
	static void addExplicitFlow(ConstructState *state, OpTpl *op, FlowFlags flags,
	                            FlowSummary &summary);

public:
	Address baseaddr;
	ConstructState rootState;
	uint4 hashCode = 0;

	FlowType getFlowType();
	std::vector<Address> getFlows();
	static const char *printFlowType(FlowType t);
	int getLength() { return length; }
	Address getFallThrough();
	int getFallThroughOffset();
	bool isFallthrough() { return flowTypeHasFallthrough(getFlowType()); }
	VarnodeData getIndirectInvar()
	{
		std::vector<FlowRecord *> curlist = flowStateList;
		for(FlowRecord *rec: curlist)
		{
			if((rec->flowFlags & (FLOW_BRANCH_INDIRECT | FLOW_CALL_INDIRECT)) != 0)
				return sleigh->dumpInvar(rec->op, baseaddr);
		}
		return VarnodeData();
	}

	SleighInstruction(R2Sleigh *s, Address &addr): sleigh(s), baseaddr(addr)
	{
		if(sleigh == nullptr)
			throw LowlevelError("Null pointer in SleighInstruction ctor");

		rootState.parent = nullptr; // rootState = new ConstructState(null);

		protoContext = sleigh->getParserContext(this);

		hashCode = hashConstructState(&rootState, 0x56c93c59);

		length = rootState.length;

		cacheTreeInfo();
	}

	~SleighInstruction()
	{
		if(protoContext)
			delete protoContext;

		flowStateListNamed.push_back(flowStateList);

		for(auto outer = flowStateListNamed.begin(); outer != flowStateListNamed.end(); outer++)
			for(auto inner = outer->begin(); inner != outer->end(); inner++)
				delete *inner;
	}
};

class SubParserWalker : public ParserWalker
{
public:
	SubParserWalker(const ParserContext *c): ParserWalker(c) {}

	void subTreeState(ConstructState *subtree)
	{
		point = subtree;
		depth = 0;
		breadcrumb[0] = 0;
	}
};

#endif // R2GHIDRA_SLEIGHINSTRUCTION_H