// SPDX-FileCopyrightText: 2020-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_SLEIGHINSTRUCTION_H
#define RZ_GHIDRA_SLEIGHINSTRUCTION_H

#include <vector>
#include <unordered_set>
#include "architecture.hh"
#include "sleigh_arch.hh"
#include "crc32.hh"
#include <unordered_map>
#include <list>

template<typename K, typename V>
class LRUCache
{
private:
	std::list<std::pair<K, V>> item_list;
	std::unordered_map<K, decltype(item_list.begin())> item_map;
	// This should sync cachesize with DisassemblyCache,
	// but default setting of it is just 2 elements cached.
	// So disable this cache for now.
	const size_t cache_size = 32;

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

static ghidra::uint4 hashConstructState(ghidra::ConstructState *cs, ghidra::uint4 hashCode)
{
	if(cs->ct == nullptr)
		return hashCode;

	ghidra::uint4 id = cs->ct->getId();
	hashCode = ghidra::crc_update(hashCode, id >> 8);
	hashCode = ghidra::crc_update(hashCode, id);

	for(ghidra::ConstructState *p: cs->resolve)
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
	ghidra::ConstructState *point = nullptr;          // The current node being visited
	const std::vector<ghidra::OpTpl *> *oparray = nullptr; // current array of ops being traversed
	ghidra::int4 depth;                               // Depth of current node within the tree
	ghidra::int4 breadcrumb[64];                      // Path of operands from the root
	int maxsize;                              // Maximum number of directives for this point
	int sectionnum;

	void setupPoint()
	{
		maxsize = 0;
		oparray = nullptr;
		ghidra::Constructor *ct = point->ct;
		if(ct == nullptr)
			return;
		const ghidra::ConstructTpl *tpl;
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
	OpTplWalker(ghidra::ConstructState *root, int sectionnum): point(root), sectionnum(sectionnum)
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
	OpTplWalker(ghidra::ConstructTpl *tpl)
	{
		depth = 0;
		breadcrumb[0] = 0;
		oparray = &tpl->getOpvec();
		maxsize = oparray->size();
	}

	ghidra::ConstructState *getState() { return point; }

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

	int nextOpTpl(ghidra::OpTpl *(&lastop))
	{
		int curind = breadcrumb[depth]++;
		if(curind >= maxsize)
			return -1;
		if(oparray == nullptr)
			// Plus one to avoid overlay when zero appear, which means return truly lastop
			return curind + 1; // Virtual build directive
		ghidra::OpTpl *op = (*oparray)[curind];
		if(op->getOpcode() != ghidra::OpCode::CPUI_MULTIEQUAL)
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

class SleighInstructionPrototype;
class SleighParserContext : public ghidra::ParserContext
{
private:
	SleighInstructionPrototype *prototype = nullptr;

public:
	SleighParserContext(ghidra::ContextCache *ccache, ghidra::Translate *trans): ParserContext(ccache, trans) {}
	SleighInstructionPrototype *getPrototype() { return prototype; }
	void setPrototype(SleighInstructionPrototype *p);
};

class SleighInstruction;
class SleighInstructionPrototype;
class RizinSleigh : public ghidra::Sleigh
{
	// To export protected member functions to SleighInstructionPrototype
	friend SleighInstructionPrototype;

private:
	ghidra::LoadImage *rizin_loader = nullptr;
	mutable LRUCache<ghidra::uintm, SleighInstruction *> ins_cache;
	mutable std::unordered_map<ghidra::uint4, SleighInstructionPrototype *> proto_cache;

	void generateLocation(const ghidra::VarnodeTpl *vntpl, ghidra::VarnodeData &vn, ghidra::ParserWalker &walker);
	void generatePointer(const ghidra::VarnodeTpl *vntpl, ghidra::VarnodeData &vn, ghidra::ParserWalker &walker);

public:
	RizinSleigh(ghidra::LoadImage *ld, ghidra::ContextDatabase *c_db): rizin_loader(ld), Sleigh(ld, c_db) {}
	~RizinSleigh() { clearCache(); }

	void reset(ghidra::LoadImage *ld, ghidra::ContextDatabase *c_db) { rizin_loader = ld; Sleigh::reset(ld, c_db); }
	void reconstructContext(ghidra::ParserContext &protoContext);
	SleighParserContext *newSleighParserContext(ghidra::Address &addr, SleighInstructionPrototype *proto);
	SleighParserContext *getParserContext(ghidra::Address &addr, SleighInstructionPrototype *proto);

	SleighInstructionPrototype *getPrototype(SleighInstruction *context);
	SleighInstruction *getInstruction(ghidra::Address &addr);

	ghidra::VarnodeData dumpInvar(ghidra::OpTpl *op, ghidra::Address &addr);

	void resolve(SleighParserContext &pos) const;
	void clearCache();
	LRUCache<ghidra::uintm, SleighInstruction *> *getInsCache() { return &ins_cache; }

	ghidra::ParserContext *getContext(const ghidra::Address &addr, ghidra::int4 state) const
	{
		return obtainContext(addr, state);
	}
};

struct SleighInstruction
{
	ghidra::Address baseaddr;
	SleighInstructionPrototype *proto = nullptr;

	SleighInstruction(ghidra::Address &addr): baseaddr(addr) {}

	FlowType getFlowType();
	std::vector<ghidra::Address> getFlows();
	SleighParserContext *getParserContext();
	SleighParserContext *getParserContext(ghidra::Address &addr);
	ghidra::Address getFallThrough();
	ghidra::VarnodeData getIndirectInvar();
};

class SleighInstructionPrototype
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
		ghidra::ConstructState *addressnode =
		    nullptr;         // Constructor state containing destination address of flow
		ghidra::OpTpl *op = nullptr; // The pcode template producing the flow
		FlowFlags flowFlags = FlowFlags(0); // flags associated with this flow
	};

	struct FlowSummary
	{
		int delay = 0;
		bool hasCrossBuilds = false;
		std::vector<FlowRecord *> flowState;
		ghidra::OpTpl *lastop = nullptr;
	};

	FlowType flowType = FlowType::INVALID;
	int delaySlotByteCnt = 0;
	ghidra::int4 length = 0;
	bool hasCrossBuilds = false;
	std::vector<FlowRecord *> flowStateList;
	std::vector<std::vector<FlowRecord *>> flowStateListNamed;
	RizinSleigh *sleigh = nullptr;

	FlowFlags gatherFlags(FlowFlags curflags, SleighInstruction *inst, int secnum);
	void gatherFlows(std::vector<ghidra::Address> &res, SleighInstruction *inst, int secnum);
	ghidra::Address getHandleAddr(ghidra::FixedHandle &hand, ghidra::AddrSpace *curSpace);
	static FlowType convertFlowFlags(FlowFlags flags);
	static FlowType flowListToFlowType(std::vector<FlowRecord *> &flowstate);
	static bool handleIsInvalid(ghidra::FixedHandle &hand);
	static FlowSummary walkTemplates(OpTplWalker &walker);
	static void addExplicitFlow(ghidra::ConstructState *state, ghidra::OpTpl *op, FlowFlags flags,
	                            FlowSummary &summary);

public:
	SleighInstruction *inst = nullptr;
	ghidra::ConstructState rootState;
	ghidra::uint4 hashCode = 0;

	FlowType getFlowType(SleighInstruction *inst);
	std::vector<ghidra::Address> getFlows(SleighInstruction *inst);
	static const char *printFlowType(FlowType t);
	int getLength() { return length; }
	ghidra::Address getFallThrough(SleighInstruction *inst);
	int getFallThroughOffset(SleighInstruction *inst);
	// bool isFallthrough() { return flowTypeHasFallthrough(getFlowType()); }
	SleighParserContext *getParserContext(ghidra::Address &addr) { return sleigh->getParserContext(addr, this); }
	void cacheTreeInfo(); // It could be renamed to parse(), but keep original name to ease update
	ghidra::VarnodeData getIndirectInvar(SleighInstruction *ins);

	SleighInstructionPrototype(RizinSleigh *s, SleighInstruction *i): sleigh(s), inst(i)
	{
		if(sleigh == nullptr)
			throw ghidra::LowlevelError("Null pointer in SleighInstructionPrototype ctor");

		rootState.parent = nullptr; // rootState = new ConstructState(null);
		rootState.ct = nullptr;
		rootState.length = rootState.offset = 0;
		rootState.hand.space = rootState.hand.offset_space = rootState.hand.temp_space = nullptr;
		rootState.hand.size = rootState.hand.offset_offset = rootState.hand.offset_size = rootState.hand.temp_offset = 0;

		SleighParserContext *protoContext = sleigh->newSleighParserContext(inst->baseaddr, this);
		sleigh->resolve(*protoContext);
		delete protoContext;
		hashCode = hashConstructState(&rootState, 0x56c93c59);
		// std::cerr << inst->baseaddr << ": 0x" << hex << hashCode << std::endl;

		length = rootState.length;
	}

	~SleighInstructionPrototype()
	{
		flowStateListNamed.push_back(flowStateList);
		for(auto outer = flowStateListNamed.begin(); outer != flowStateListNamed.end(); outer++)
			for(auto inner = outer->begin(); inner != outer->end(); inner++)
				delete *inner;

		clearRootState(&rootState);
	}

	void clearRootState(ghidra::ConstructState *curr)
	{
		// Classic DFS
		if(curr)
		{
			for(auto iter = curr->resolve.begin(); iter != curr->resolve.end(); ++iter)
			{
				if(*iter)
					clearRootState(*iter);
				delete *iter;
			}
		}
	}
};

class SleighParserWalker : public ghidra::ParserWalkerChange
{
public:
	SleighParserWalker(ghidra::ParserContext *c): ParserWalkerChange(c) {}

	void subTreeState(ghidra::ConstructState *subtree)
	{
		point = subtree;
		depth = 0;
		breadcrumb[0] = 0;
	}

	void allocateOperand(ghidra::int4 i)
	{
		ghidra::ConstructState *opstate = new ghidra::ConstructState;
		opstate->ct = nullptr;
		opstate->parent = point;
		opstate->length = opstate->offset = 0;
		opstate->hand.space = opstate->hand.offset_space = opstate->hand.temp_space = nullptr;
		opstate->hand.size = opstate->hand.offset_offset = opstate->hand.offset_size = opstate->hand.temp_offset = 0;

		point->resolve.emplace_back(opstate);
		breadcrumb[depth++] += 1;
		point = opstate;
		breadcrumb[depth] = 0;
	}
};

#endif // RZ_GHIDRA_SLEIGHINSTRUCTION_H
