/* radare - LGPL - Copyright 2020 - FXTi */

#include <r_lib.h>
#include <r_anal.h>
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cfenv>
#include "SleighAsm.h"

static SleighAsm sanal;

static int archinfo(RAnal *anal, int query)
{
	// This is to check if RCore plugin set cpu properly.
	ut64 length = strlen(anal->cpu), i = 0;
	for(; i < length && anal->cpu[i] != ':'; ++i) {}
	if(i == length)
		return -1;

	sanal.init(anal->cpu, anal? anal->iob.io : nullptr, SleighAsm::getConfig(anal));

	if(query == R_ANAL_ARCHINFO_ALIGN)
		return sanal.alignment;
	else
		return -1;
}

static std::vector<std::string> string_split(const std::string &s)
{
	std::vector<std::string> tokens;
	for(ut64 i = 0; i < s.size();)
	{
		std::string tmp;
		while(!std::isalnum(s[i]))
			++i;
		while(std::isalnum(s[i]))
			tmp.push_back(s[i++]);
		tokens.emplace_back(tmp);
	}
	return tokens;
}

class InnerAssemblyEmit : public AssemblyEmit
{
public:
	std::string args;

	void dump(const Address &addr, const string &mnem, const string &body) override
	{
		for(auto iter = body.cbegin(); iter != body.cend(); ++iter)
			if(*iter != '[' && *iter != ']')
				args.push_back(*iter);
	}
};

template<typename T>
static inline T inner_max(T foo, T bar)
{
	return foo > bar? foo: bar;
}

static int get_reg_type(const std::string &name);

static RAnalValue resolve_arg(RAnal *anal, const PcodeOperand *arg)
{
	RAnalValue res;
	memset(&res, 0, sizeof(RAnalValue));

	if(arg->is_const())
	{
		res.type = R_ANAL_VAL_IMM;
		res.imm = arg->number;
	}
	else if(arg->is_reg())
	{
		res.type = R_ANAL_VAL_REG;
		res.reg = r_reg_get(anal->reg, arg->name.c_str(), get_reg_type(arg->name));
	}
	else if(arg->is_ram())
	{
		res.type = R_ANAL_VAL_MEM;
		res.base = arg->offset;
		res.memref = arg->size;
	}
	else
	{ // PcodeOperand::UNIQUE
		const Pcodeop *curr_op = ((UniquePcodeOperand *)arg)->def;
		RAnalValue in0, in1;
		memset(&in0, 0, sizeof(RAnalValue));
		memset(&in1, 0, sizeof(RAnalValue));

		if(curr_op->input0)
		{
			in0 = resolve_arg(anal, curr_op->input0);
			if(in0.absolute == -1)
				return in0;
		}
		if(curr_op->input1)
		{
			in1 = resolve_arg(anal, curr_op->input1);
			if(in1.absolute == -1)
				return in1;
		}

		switch(curr_op->type)
		{
			case CPUI_INT_ZEXT:
			case CPUI_INT_SEXT:
			case CPUI_SUBPIECE:
			case CPUI_COPY: res = in0; break;

			case CPUI_LOAD:
				res = in1;
				res.type = R_ANAL_VAL_MEM;
				res.memref = curr_op->input1->size;
				break;

			case CPUI_INT_ADD:
			{
				if(in0.type == R_ANAL_VAL_MEM || in1.type == R_ANAL_VAL_MEM)
					res.type = R_ANAL_VAL_MEM;
				else if(in0.type == R_ANAL_VAL_REG || in1.type == R_ANAL_VAL_REG)
					res.type = R_ANAL_VAL_REG;
				else
					res.type = R_ANAL_VAL_IMM;

				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.imm && in1.imm)
					res.imm = in0.imm + in1.imm;
				else
					res.base = in0.imm + in1.imm + in0.base + in1.base;
				res.mul = inner_max(in0.mul, in1.mul); // Only one of inputs should set mul

				res.delta = inner_max(in0.delta, in1.delta);
				if(in0.reg && in1.reg)
				{
					res.reg = in0.reg;
					res.regdelta = in1.reg;
				}
				else
				{
					res.reg = in0.reg? in0.reg: in1.reg;
					res.regdelta = in0.regdelta? in0.regdelta: in1.regdelta;
				}
				break;
			}

			case CPUI_INT_SUB:
			{
				if(in0.type == R_ANAL_VAL_MEM || in1.type == R_ANAL_VAL_MEM)
					res.type = R_ANAL_VAL_MEM;
				else if(in0.type == R_ANAL_VAL_REG || in1.type == R_ANAL_VAL_REG)
					res.type = R_ANAL_VAL_REG;
				else
					res.type = R_ANAL_VAL_IMM;

				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.imm && in1.imm)
					res.imm = in0.imm - in1.imm;
				else
					res.base = (in0.imm + in0.base) - (in1.imm + in1.base);
				res.mul = inner_max(in0.mul, in1.mul); // Only one of inputs should set mul
				res.delta = inner_max(in0.delta, in1.delta);
				if(in0.reg && in1.reg)
				{
					res.reg = in0.reg;
					res.regdelta = in1.reg;
				}
				else
				{
					res.reg = in0.reg? in0.reg: in1.reg;
					res.regdelta = in0.regdelta? in0.regdelta: in1.regdelta;
				}
				break;
			}

			case CPUI_INT_MULT:
			{
				// 3 cases:
				// imm (CONST) * imm (CONST)
				// imm (CONST) * base (RAM)
				// imm (CONST) * reg (REGISTER)
				if(in0.type == R_ANAL_VAL_MEM || in1.type == R_ANAL_VAL_MEM)
					res.type = R_ANAL_VAL_MEM;
				else if(in0.type == R_ANAL_VAL_REG || in1.type == R_ANAL_VAL_REG)
					res.type = R_ANAL_VAL_REG;
				else
					res.type = R_ANAL_VAL_IMM;

				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.imm && in1.imm)
				{
					res.imm = in0.imm * in1.imm;
				}
				else if(in0.imm && in1.base)
				{
					res.mul = in0.imm;
					res.delta = in1.base;
				}
				else if(in0.base && in1.imm)
				{
					res.mul = in1.imm;
					res.delta = in0.base;
				}
				else if(in0.imm && in1.reg)
				{
					res.mul = in0.imm;
					res.regdelta = in1.reg;
				}
				else if(in0.reg && in1.imm)
				{
					res.mul = in1.imm;
					res.regdelta = in0.reg;
				}
				else
					res.absolute = -1; // Means invalid

				break;
			}

			case CPUI_INT_AND:
			{
				// Should only happen when const need some modification.
				res.type = in0.type;
				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.imm && in1.imm)
					res.imm = in0.imm & in1.imm;
				else
					res.absolute = -1; // Means invalid
				break;
			}

			case CPUI_INT_OR:
			{
				// Should only happen when const need some modification.
				res.type = in0.type;
				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.imm && in1.imm)
					res.imm = in0.imm | in1.imm;
				else
					res.absolute = -1; // Means invalid
				break;
			}

			case CPUI_INT_XOR:
			{
				// Should only happen when const need some modification.
				res.type = in0.type;
				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.imm && in1.imm)
					res.imm = in0.imm ^ in1.imm;
				else
					res.absolute = -1; // Means invalid
				break;
			}

			default: res.absolute = -1; // Means invalid
		}
	}

	return res;
}

static std::vector<RAnalValue> resolve_out(RAnal *anal,
                                           std::vector<Pcodeop>::const_iterator curr_op,
                                           std::vector<Pcodeop>::const_iterator end_op,
                                           const PcodeOperand *arg)
{
	std::vector<RAnalValue> res;
	RAnalValue tmp;
	memset(&tmp, 0, sizeof(tmp));

	if(arg->is_const())
	{
		tmp.type = R_ANAL_VAL_IMM;
		tmp.imm = arg->number;
		res.push_back(tmp);
	}
	else if(arg->is_reg())
	{
		tmp.type = R_ANAL_VAL_REG;
		tmp.reg = r_reg_get(anal->reg, arg->name.c_str(), get_reg_type(arg->name));
		res.push_back(tmp);
	}
	else if(arg->is_ram())
	{
		tmp.type = R_ANAL_VAL_MEM;
		tmp.base = arg->offset;
		tmp.memref = arg->size;
		res.push_back(tmp);
	}
	else
	{
		// auto iter = raw_ops.cebgin()
		// for (; iter != raw_ops.cend() && &(*iter) != curr_op; ++iter) {}
		auto iter = curr_op;

		while(++iter != end_op)
		{
			if(iter->type == CPUI_STORE)
			{
				if(iter->output && *iter->output == *arg && iter->input1)
				{
					tmp = resolve_arg(anal, iter->input1);
					if(tmp.absolute != -1)
						res.push_back(tmp);
				}
			}
			else
			{
				if((iter->input0 && *iter->input0 == *arg) ||
				   (iter->input1 && *iter->input1 == *arg))
				{
					if(iter->output && iter->output->is_reg())
					{
						memset(&tmp, 0, sizeof(tmp));
						tmp.type = R_ANAL_VAL_REG;
						tmp.reg = r_reg_get(anal->reg, iter->output->name.c_str(),
						                    get_reg_type(iter->output->name));
						res.push_back(tmp);
					}
				}
			}
		}
	}

	return res;
}

static inline bool arg_set_has(const std::unordered_set<std::string> &arg_set,
                               const RAnalValue &value)
{
	if(value.reg && arg_set.find(value.reg->name) != arg_set.end())
		return true;
	if(value.regdelta && arg_set.find(value.regdelta->name) != arg_set.end())
		return true;
	return false;
}

static RAnalValue *anal_value_dup(const RAnalValue &from)
{
	RAnalValue *to = r_anal_value_new();
	if(!to)
		return to;
	*to = from;
	return to;
}

/* After some consideration, I decide to classify mov operation:
 * R_ANAL_OP_TYPE_STORE:
 *     REG -> MEM (Key: STORE)
 *     REG -> MEM (Key: COPY)
 * R_ANAL_OP_TYPE_LOAD:
 *     MEM -> REG (Key: LOAD)
 *     MEM -> REG (Key: COPY)
 * R_ANAL_OP_TYPE_MOV:
 *     IMM   -> REG (Key: COPY)
 *     REG   -> REG (Key: COPY)
 *     CONST -> REG (Key: COPY)
 *     CONST -> MEM (Key: STORE)
 *     MEM   -> MEM (Key: LOAD & STORE) // Never happen as far as I know
 */

static ut32 anal_type_MOV(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &arg_set)
{
	const ut32 this_type = R_ANAL_OP_TYPE_MOV;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	const PcodeOpType key_pcode_store = CPUI_STORE;
	RAnalValue in0, out;
	memset(&in0, 0, sizeof(in0));
	memset(&out, 0, sizeof(out));
	std::vector<RAnalValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_copy)
		{
			if(iter->output)
				outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

			auto p = outs.cbegin();
			for(; p != outs.cend() && !arg_set_has(arg_set, *p); ++p) {}
			if(p != outs.cend())
			{
				out = *p;

				if(iter->input0)
					in0 = resolve_arg(anal, iter->input0);

				if(in0.imm || arg_set_has(arg_set, in0))
				{
					anal_op->type = this_type;
					anal_op->src[0] = anal_value_dup(in0);
					anal_op->dst = anal_value_dup(out);

					return this_type;
				}
			}
		}

		if(iter->type == key_pcode_store)
		{
			if(iter->output)
				in0 = resolve_arg(anal, iter->output);

			if(iter->input1)
				out = resolve_arg(anal, iter->input1);
			out.memref = iter->output->size;

			if(in0.imm && iter->input1 && out.absolute != -1)
			{
				anal_op->type = this_type;
				anal_op->src[0] = anal_value_dup(in0);
				anal_op->dst = anal_value_dup(out);

				return this_type;
			}
		}
	}

	return 0;
}

static ut32 anal_type_LOAD(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &arg_set)
{
	/*
	 * R_ANAL_OP_TYPE_LOAD:
	 *     MEM -> REG (Key: LOAD)
	 *     MEM -> REG (Key: COPY)
	 */
	const ut32 this_type = R_ANAL_OP_TYPE_LOAD;
	const PcodeOpType key_pcode_load = CPUI_LOAD;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	RAnalValue in0, out;
	memset(&in0, 0, sizeof(in0));
	memset(&out, 0, sizeof(out));
	std::vector<RAnalValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_load || iter->type == key_pcode_copy)
		{
			if(iter->output)
				outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

			auto p = outs.cbegin();
			for(; p != outs.cend() && !arg_set_has(arg_set, *p); ++p) {}
			if(p != outs.cend())
			{
				out = *p;

				if(iter->type == key_pcode_load? iter->input1: iter->input0)
				{
					in0 = resolve_arg(anal,
					                  iter->type == key_pcode_load? iter->input1: iter->input0);
					if(iter->type == key_pcode_load) in0.memref = iter->output->size;
				}

				if(in0.absolute != -1 && in0.memref)
				{
					anal_op->type = this_type;
					anal_op->src[0] = anal_value_dup(in0);
					anal_op->dst = anal_value_dup(out);

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 anal_type_STORE(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                            const std::unordered_set<std::string> &arg_set)
{
	/*
	 * R_ANAL_OP_TYPE_STORE:
	 *     REG -> MEM (Key: STORE)
	 *     REG -> MEM (Key: COPY)
	 */
	const ut32 this_type = R_ANAL_OP_TYPE_STORE;
	const PcodeOpType key_pcode_store = CPUI_STORE;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	RAnalValue in0, out;
	memset(&in0, 0, sizeof(in0));
	memset(&out, 0, sizeof(out));
	std::vector<RAnalValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_store)
		{
			if(iter->output && iter->input1)
				in0 = resolve_arg(anal, iter->output);

			if(in0.absolute == -1 || !arg_set_has(arg_set, in0))
				continue;

			out = resolve_arg(anal, iter->input1);
			out.memref = iter->output->size;

			if(out.absolute != -1 && out.memref)
			{
				anal_op->type = this_type;
				anal_op->src[0] = anal_value_dup(in0);
				anal_op->dst = anal_value_dup(out);

				return this_type;
			}
		}

		if(iter->type == key_pcode_copy)
		{
			if(iter->input0 && iter->output)
				in0 = resolve_arg(anal, iter->input0);

			if(in0.absolute == -1 || !arg_set_has(arg_set, in0))
				continue;

			outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

			auto p = outs.cbegin();
			for(; p != outs.cend(); ++p)
			{
				out = *p;

				if(out.absolute != -1 && out.memref)
				{
					anal_op->type = this_type;
					anal_op->src[0] = anal_value_dup(in0);
					anal_op->dst = anal_value_dup(out);

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 anal_type_XSWI(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &arg_set)
{
	// R_ANAL_OP_TYPE_CSWI
	// R_ANAL_OP_TYPE_SWI
	const PcodeOpType key_pcode_callother = CPUI_CALLOTHER;
	const PcodeOpType key_pcode_cbranch = CPUI_CBRANCH;
	bool has_cbranch = false;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_cbranch)
			has_cbranch = true;

		if(iter->type == key_pcode_callother)
		{
			if(iter->input1)
				anal_op->val = iter->input1->number;

			anal_op->type = has_cbranch? R_ANAL_OP_TYPE_CSWI: R_ANAL_OP_TYPE_SWI;

			return anal_op->type;
		}
	}

	return 0;
}

static ut32 anal_type_XPUSH(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                            const std::unordered_set<std::string> &arg_set)
{
	// R_ANAL_OP_TYPE_UPUSH
	// R_ANAL_OP_TYPE_RPUSH
	// R_ANAL_OP_TYPE_PUSH
	const PcodeOpType key_pcode = CPUI_STORE;
	RAnalValue out, in;
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode)
		{
			if(iter->input1)
			{
				out = resolve_arg(anal, iter->input1);
				out.memref = iter->output->size;
			}

			if((out.reg && sanal.reg_mapping[sanal.sp_name] == out.reg->name) ||
			   (out.regdelta && sanal.reg_mapping[sanal.sp_name] == out.regdelta->name))
			{
				anal_op->type = R_ANAL_OP_TYPE_UPUSH;
				anal_op->stackop = R_ANAL_STACK_INC;

				if(iter->output)
					in = resolve_arg(anal, iter->output);

				if(arg_set_has(arg_set, in))
					anal_op->type = R_ANAL_OP_TYPE_RPUSH;
				anal_op->src[0] = anal_value_dup(in);
				anal_op->dst = anal_value_dup(out);

				return anal_op->type;
			}
		}
	}

	return 0;
}

static ut32 anal_type_POP(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &arg_set)
{
	const ut32 this_type = R_ANAL_OP_TYPE_POP;
	const PcodeOpType key_pcode = CPUI_LOAD;
	RAnalValue in0, out;
	memset(&in0, 0, sizeof(in0));
	memset(&out, 0, sizeof(out));
	std::vector<RAnalValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode)
		{
			if(iter->input1)
				in0 = resolve_arg(anal, iter->input1);

			if((in0.reg && sanal.reg_mapping[sanal.sp_name] == in0.reg->name) ||
			   (in0.regdelta && sanal.reg_mapping[sanal.sp_name] == in0.regdelta->name))
			{
				if(iter->output)
					outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

				auto p = outs.cbegin();
				for(; p != outs.cend() && !arg_set_has(arg_set, *p); ++p) {}
				if(p == outs.cend())
					continue;
				out = *p;

				anal_op->type = this_type;
				anal_op->stackop = R_ANAL_STACK_INC;
				anal_op->dst = anal_value_dup(out);
				anal_op->src[0] = anal_value_dup(in0);

				return this_type;
			}
		}
	}

	return 0;
}

static ut32 anal_type_XCMP(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &arg_set)
{
	// R_ANAL_OP_TYPE_CMP
	// R_ANAL_OP_TYPE_ACMP
	const PcodeOpType key_pcode_sub = CPUI_INT_SUB;
	const PcodeOpType key_pcode_and = CPUI_INT_AND;
	const PcodeOpType key_pcode_equal = CPUI_INT_EQUAL;
	RAnalValue in0, in1;
	memset(&in0, 0, sizeof(in0));
	memset(&in1, 0, sizeof(in1));
	uintb unique_off = 0;
	PcodeOpType key_pcode = CPUI_MAX;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_sub || iter->type == key_pcode_and)
		{
			if(iter->input0)
				in0 = resolve_arg(anal, iter->input0);

			if(iter->input1)
				in1 = resolve_arg(anal, iter->input1);
			if(!arg_set_has(arg_set, in0) && !arg_set_has(arg_set, in1))
				continue;

			if(iter->output && iter->output->is_unique())
			{
				unique_off = iter->output->offset;
				key_pcode = iter->type;
			}
		}

		if(unique_off && iter->type == key_pcode_equal)
		{
			if(!iter->input0 || !iter->input1)
				continue;

			if(iter->input0->is_const() && iter->input1->is_unique())
			{
				if(iter->input0->number != 0 || iter->input1->offset != unique_off)
					continue;
			}
			else if(iter->input0->is_unique() && iter->input1->is_const())
			{
				if(iter->input1->number != 0 || iter->input0->offset != unique_off)
					continue;
			}
			else
				continue;

			anal_op->type = key_pcode == key_pcode_sub? R_ANAL_OP_TYPE_CMP: R_ANAL_OP_TYPE_ACMP;
			// anal_op->cond = R_ANAL_COND_EQ; Should I enable this? I think sub can judge equal and
			// less or more.
			anal_op->src[0] = anal_value_dup(in0);
			anal_op->src[1] = anal_value_dup(in1);

			return anal_op->type;
		}
	}

	return 0;
}

static ut32 anal_type_INT_XXX(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                              const std::unordered_set<std::string> &arg_set)
{
	// R_ANAL_OP_TYPE_ADD
	// R_ANAL_OP_TYPE_SUB
	// R_ANAL_OP_TYPE_MUL
	// R_ANAL_OP_TYPE_DIV
	// R_ANAL_OP_TYPE_MOD
	// R_ANAL_OP_TYPE_OR
	// R_ANAL_OP_TYPE_AND
	// R_ANAL_OP_TYPE_XOR
	// R_ANAL_OP_TYPE_SHR
	// R_ANAL_OP_TYPE_SHL
	// R_ANAL_OP_TYPE_SAR
	RAnalValue in0, in1, out;
	memset(&in0, 0, sizeof(in0));
	memset(&in1, 0, sizeof(in1));
	memset(&out, 0, sizeof(out));
	std::vector<RAnalValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		switch(iter->type)
		{
			case CPUI_INT_ADD:
			case CPUI_INT_SUB:
			case CPUI_INT_MULT:
			case CPUI_INT_DIV:
			case CPUI_INT_REM:
			case CPUI_INT_SREM:
			case CPUI_INT_OR:
			case CPUI_INT_AND:
			case CPUI_INT_XOR:
			case CPUI_INT_RIGHT:
			case CPUI_INT_LEFT:
			case CPUI_INT_SRIGHT:
			{
				if(iter->input0 && iter->input1)
				{
					in0 = resolve_arg(anal, iter->input0);
					in1 = resolve_arg(anal, iter->input1);
				}
				if(arg_set_has(arg_set, in0) || arg_set_has(arg_set, in1))
				{
					if(iter->output)
						outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

					auto p = outs.cbegin();
					for(; p != outs.cend() && !arg_set_has(arg_set, *p); ++p) {}
					if(p != outs.cend())
					{
						out = *p;

						switch(iter->type)
						{
							case CPUI_INT_ADD: anal_op->type = R_ANAL_OP_TYPE_ADD; break;
							case CPUI_INT_SUB: anal_op->type = R_ANAL_OP_TYPE_SUB; break;
							case CPUI_INT_MULT: anal_op->type = R_ANAL_OP_TYPE_MUL; break;
							case CPUI_INT_DIV: anal_op->type = R_ANAL_OP_TYPE_DIV; break;
							case CPUI_INT_REM:
							case CPUI_INT_SREM: anal_op->type = R_ANAL_OP_TYPE_MOD; break;
							case CPUI_INT_OR: anal_op->type = R_ANAL_OP_TYPE_OR; break;
							case CPUI_INT_AND: anal_op->type = R_ANAL_OP_TYPE_AND; break;
							case CPUI_INT_XOR: anal_op->type = R_ANAL_OP_TYPE_XOR; break;
							case CPUI_INT_RIGHT: anal_op->type = R_ANAL_OP_TYPE_SHR; break;
							case CPUI_INT_LEFT: anal_op->type = R_ANAL_OP_TYPE_SHL; break;
							case CPUI_INT_SRIGHT: anal_op->type = R_ANAL_OP_TYPE_SAR; break;
							default: break;
						}
						anal_op->src[0] = anal_value_dup(in0);
						anal_op->src[1] = anal_value_dup(in1);
						anal_op->dst = anal_value_dup(out);

						return anal_op->type;
					}
				}
			}
			break;

			default: break;
		}
	}

	return 0;
}

static ut32 anal_type_NOR(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &arg_set)
{
	const ut32 this_type = R_ANAL_OP_TYPE_NOR;
	const PcodeOpType key_pcode_or = CPUI_INT_OR;
	const PcodeOpType key_pcode_negate = CPUI_INT_NEGATE;
	RAnalValue in0, in1, out;
	memset(&in0, 0, sizeof(in0));
	memset(&in1, 0, sizeof(in1));
	memset(&out, 0, sizeof(out));
	std::vector<RAnalValue> outs;
	uintb unique_off = 0;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_or)
		{
			if(iter->input0 && iter->input1)
			{
				in0 = resolve_arg(anal, iter->input0);
				in1 = resolve_arg(anal, iter->input1);
			}
			if(arg_set_has(arg_set, in0) || arg_set_has(arg_set, in1))
			{
				if(iter->output && iter->output->is_unique())
				{
					unique_off = iter->output->offset;
					continue;
				}
			}
		}
		if(unique_off && iter->type == key_pcode_negate)
		{
			if(iter->input0 && iter->input0->is_unique() && iter->input0->offset == unique_off)
			{
				if(iter->output)
					outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

				auto p = outs.cbegin();
				for(; p != outs.cend() && !arg_set_has(arg_set, *p); ++p) {}
				if(p != outs.cend())
				{
					out = *p;

					anal_op->type = this_type;
					anal_op->src[0] = anal_value_dup(in0);
					anal_op->src[1] = anal_value_dup(in1);
					anal_op->dst = anal_value_dup(out);

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 anal_type_NOT(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &arg_set)
{
	const ut32 this_type = R_ANAL_OP_TYPE_NOT;
	const PcodeOpType key_pcode = CPUI_INT_NEGATE;
	RAnalValue in0, out;
	memset(&in0, 0, sizeof(in0));
	memset(&out, 0, sizeof(out));
	std::vector<RAnalValue> outs;
	uintb unique_off = 0;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode)
		{
			if(iter->input0)
				in0 = resolve_arg(anal, iter->input0);

			if(arg_set_has(arg_set, in0))
			{
				if(iter->output)
					outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

				auto p = outs.cbegin();
				for(; p != outs.cend() && !arg_set_has(arg_set, *p); ++p) {}
				if(p != outs.cend())
				{
					out = *p;

					anal_op->type = this_type;
					anal_op->src[0] = anal_value_dup(in0);
					anal_op->dst = anal_value_dup(out);

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 anal_type_XCHG(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &arg_set)
{
	const ut32 this_type = R_ANAL_OP_TYPE_XCHG;
	const PcodeOpType key_pcode = CPUI_COPY;
	std::vector<decltype(raw_ops.cbegin())> copy_vec;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode)
			copy_vec.emplace_back(iter);
	}

	if(copy_vec.size() == 3)
	{
		if(!(*copy_vec[0]->input0 == *copy_vec[1]->output))
			goto fail;
		if(!(*copy_vec[0]->output == *copy_vec[2]->input0))
			goto fail;
		if(!(*copy_vec[1]->input0 == *copy_vec[2]->output))
			goto fail;

		anal_op->type = this_type;
		anal_op->src[0] = anal_value_dup(resolve_arg(anal, copy_vec[0]->input0));
		anal_op->dst = anal_value_dup(resolve_arg(anal, copy_vec[2]->output));

		return this_type;
	}

fail:
	return 0;
}

static ut32 anal_type_SINGLE(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                             const std::unordered_set<std::string> &arg_set)
{
	// R_ANAL_OP_TYPE_CAST
	// R_ANAL_OP_TYPE_NEW
	// R_ANAL_OP_TYPE_ABS
	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		switch(iter->type)
		{
			case CPUI_CAST: anal_op->type = R_ANAL_OP_TYPE_CAST; return anal_op->type;
			case CPUI_NEW: anal_op->type = R_ANAL_OP_TYPE_NEW; return anal_op->type;
			case CPUI_FLOAT_ABS: anal_op->type = R_ANAL_OP_TYPE_ABS; return anal_op->type;
			default: break;
		}
	}

	return 0;
}

static void anal_type(RAnal *anal, RAnalOp *anal_op, PcodeSlg &pcode_slg, InnerAssemblyEmit &assem)
{
	std::vector<std::string> args = string_split(assem.args);
	std::unordered_set<std::string> arg_set;
	std::map<VarnodeData, std::string> reglist;
	sanal.trans.getAllRegisters(reglist);
	for(auto iter = args.cbegin(); iter != args.cend(); ++iter)
	{
		for(auto p = reglist.cbegin(); p != reglist.cend(); ++p)
		{
			if(p->second == *iter)
			{
				arg_set.insert(sanal.reg_mapping[*iter]);
				break;
			}
		}
	}

	std::unordered_map<uintb, const Pcodeop *> midvar_op;
	for(auto pco = pcode_slg.pcodes.begin(); pco != pcode_slg.pcodes.end(); ++pco)
	{

		if(pco->input0 && pco->input0->is_unique())
		{
			UniquePcodeOperand *tmp = new UniquePcodeOperand(pco->input0);
			delete pco->input0;
			pco->input0 = (PcodeOperand *)tmp;
			tmp->def = midvar_op[tmp->offset];
		}
		if(pco->input1 && pco->input1->is_unique())
		{
			UniquePcodeOperand *tmp = new UniquePcodeOperand(pco->input1);
			delete pco->input1;
			pco->input1 = (PcodeOperand *)tmp;
			tmp->def = midvar_op[tmp->offset];
		}

		if(pco->type != CPUI_STORE)
		{
			// You should know this case:
			// (unique, 0xffff, 4) = INT_ADD (unique, 0xffff, 4), 2
			// Even unique varnode can be overwritten!
			// Here midvar_op will always track the latest define place.
			if(pco->output && pco->output->is_unique())
				midvar_op[pco->output->offset] = &(*pco);
		}
		else
		{
			if(pco->output && pco->output->is_unique())
			{
				UniquePcodeOperand *tmp = new UniquePcodeOperand(pco->output);
				delete pco->output;
				pco->output = (PcodeOperand *)tmp;
				tmp->def = midvar_op[tmp->offset];
			}
		}
	}

	anal_op->type = R_ANAL_OP_TYPE_UNK;

	if(anal_type_XCHG(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_SINGLE(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_XSWI(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_XCMP(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_NOR(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_XPUSH(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_POP(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_STORE(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_LOAD(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_INT_XXX(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_NOT(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_MOV(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;

	return;
}

static char *getIndirectReg(SleighInstruction &ins, bool &isRefed)
{
	VarnodeData data = ins.getIndirectInvar();
	isRefed = data.size & 0x80000000;
	if(isRefed)
		data.size &= ~0x80000000;

	AddrSpace *space = data.space;
	if(space->getName() == "register")
		return strdup(
		    sanal
		        .reg_mapping[space->getTrans()->getRegisterName(data.space, data.offset, data.size)]
		        .c_str());
	else
		return nullptr;
}

static int index_of_unique(const std::vector<PcodeOperand *> &esil_stack, const PcodeOperand *arg)
{
	int index = 1;
	for(auto iter = esil_stack.crbegin(); iter != esil_stack.crend(); ++iter, ++index)
		if(*iter && **iter == *arg)
			return index;

	return -1;
}

static void sleigh_esil(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len,
                        const std::vector<Pcodeop> &Pcodes)
{
	std::vector<PcodeOperand *> esil_stack;
	stringstream ss;

	auto print_if_unique = [&esil_stack, &ss](const PcodeOperand *arg, int offset = 0) -> bool {
		if(arg->is_unique())
		{
			int index = index_of_unique(esil_stack, arg);
			if(-1 == index)
				throw LowlevelError(
				    "print_if_unique: Can't find required unique varnodes in stack.");

			ss << index + offset << ",PICK";

			return true;
		}
		else
			return false;
	};

	auto push_stack = [&esil_stack](PcodeOperand *arg = nullptr) {
		if(!arg)
			throw LowlevelError("push_stack: arg is nullptr.");

		esil_stack.push_back(arg);
	};

	for(auto iter = Pcodes.cbegin(); iter != Pcodes.cend(); ++iter)
	{
		switch(iter->type)
		{
			// FIXME: Maybe some of P-codes below can be processed
			// In dalvik: 0x00000234: array_length 0x1008,0x1008
			//                v2 = CPOOLREF v2, 0x0, 0x6
			case CPUI_CPOOLREF:
			case CPUI_CALLOTHER:
			case CPUI_NEW:
			case CPUI_SEGMENTOP:
			case CPUI_INSERT:
			case CPUI_EXTRACT: /* Above don't have explicit definition */
			case CPUI_MULTIEQUAL:
			case CPUI_INDIRECT:
			case CPUI_CAST:
			case CPUI_PTRADD:
			case CPUI_PTRSUB: /* Above are not raw P-code */
			branch_in_pcodes:
				// ss << ",CLEAR,TODO";
				ss.str("");
				esil_stack.clear();
				iter = --Pcodes.cend(); // Jump out
				break;

			case CPUI_INT_ZEXT:
			case CPUI_INT_SEXT:
			{
				if(iter->input0 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");

					if(iter->type == CPUI_INT_SEXT)
					{
						ss << "," << iter->input0->size * 8 << ",SWAP,SIGN";
						ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,&";
					}

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_COPY:
			{
				if(iter->input0 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
					{
						if(!iter->input0->is_ram())
							ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
						else
							ss << *iter->input0 << ",[" << iter->input0->size << "]";
					}

					if(iter->output->is_unique())
						push_stack(iter->output);
					else if(iter->output->is_ram())
						ss << "," << *iter->output << ",=[" << iter->output->size << "]";
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_LOAD:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					if(iter->input0->is_const() &&
					   ((AddrSpace *)iter->input0->offset)->getWordSize() != 1)
						ss << "," << ((AddrSpace *)iter->input0->offset)->getWordSize() << ",*";
					ss << ",[" << iter->output->size << "]";

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_STORE:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->output))
						ss << *iter->output << (iter->output->is_reg()? ",GET": "");

					ss << ",";
					if(!print_if_unique(iter->input1, 1))
						ss << *iter->input1;
					if(iter->input0->is_const() &&
					   ((AddrSpace *)iter->input0->offset)->getWordSize() != 1)
						ss << "," << ((AddrSpace *)iter->input0->offset)->getWordSize() << ",*";
					ss << ",=[" << iter->output->size << "]";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			// TODO: CPUI_BRANCH can jump in the other P-codes of instruction
			// Three P-codes below are all indirect style
			case CPUI_RETURN:
			case CPUI_CALLIND:
			case CPUI_BRANCHIND: // Actually, I have some suspect about this.
			// End here.
			case CPUI_CALL:
			case CPUI_BRANCH:
			{
				if(iter->input0)
				{
					if(iter->input0->is_const())
						// throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
						// This means conditional jump in P-codes
						goto branch_in_pcodes;
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << "," << sanal.reg_mapping[sanal.pc_name] << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_CBRANCH:
			{
				if(iter->input0 && iter->input1)
				{
					ss << ",";
					if(!print_if_unique(iter->input1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << ",?{";

					if(iter->input0->is_const())
						// throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
						// This means conditional jump in P-codes
						goto branch_in_pcodes;
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << "," << sanal.reg_mapping[sanal.pc_name] << ",=,}";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_PIECE:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << "," << iter->input1->size * 8 << ",SWAP,<<";

					ss << ",";
					if(!print_if_unique(iter->input1, 1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << ",|";
					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_SUBPIECE:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					if(!iter->input1->is_const())
						throw LowlevelError("sleigh_esil: input1 is not consts in SUBPIECE.");
					ss << "," << iter->input1->number * 8 << ",SWAP,>>";

					if(iter->output->size < iter->input0->size + iter->input1->number)
						ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,&";

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_FLOAT_EQUAL:
			case CPUI_FLOAT_NOTEQUAL:
			case CPUI_FLOAT_LESS:
			case CPUI_FLOAT_LESSEQUAL:
			case CPUI_FLOAT_ADD:
			case CPUI_FLOAT_SUB:
			case CPUI_FLOAT_MULT:
			case CPUI_FLOAT_DIV:
			case CPUI_INT_LESS:
			case CPUI_INT_SLESS:
			case CPUI_INT_LESSEQUAL:
			case CPUI_INT_SLESSEQUAL:
			case CPUI_INT_NOTEQUAL:
			case CPUI_INT_EQUAL:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << ",";
					switch(iter->type)
					{
						case CPUI_FLOAT_EQUAL: ss << "F=="; break;
						case CPUI_FLOAT_NOTEQUAL: ss << "F!="; break;
						case CPUI_FLOAT_LESS: ss << "F<"; break;
						case CPUI_FLOAT_LESSEQUAL: ss << "F<="; break;
						case CPUI_FLOAT_ADD:
							ss << "F+," << iter->output->size << ",SWAP,F2F";
							break;
						case CPUI_FLOAT_SUB: ss << "F-" << iter->output->size << ",SWAP,F2F"; break;
						case CPUI_FLOAT_MULT:
							ss << "F*" << iter->output->size << ",SWAP,F2F";
							break;
						case CPUI_FLOAT_DIV: ss << "F/" << iter->output->size << ",SWAP,F2F"; break;
						case CPUI_INT_SLESS:
							ss << iter->input0->size * 8 << ",SWAP,SIGN,SWAP,"
							   << iter->input1->size * 8 << ",SWAP,SIGN,SWAP,";
						case CPUI_INT_LESS: ss << "<"; break;
						case CPUI_INT_SLESSEQUAL:
							ss << iter->input0->size * 8 << ",SWAP,SIGN,SWAP,"
							   << iter->input1->size * 8 << ",SWAP,SIGN,SWAP,";
						case CPUI_INT_LESSEQUAL: ss << "<="; break;
						case CPUI_INT_NOTEQUAL: ss << "==,!"; break;
						case CPUI_INT_EQUAL: ss << "=="; break;
					}

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_INT_MULT:
			case CPUI_INT_DIV:
			case CPUI_INT_REM:
			case CPUI_INT_SDIV:
			case CPUI_INT_SREM:
			case CPUI_BOOL_XOR:
			case CPUI_INT_XOR:
			case CPUI_BOOL_AND:
			case CPUI_INT_AND:
			case CPUI_BOOL_OR:
			case CPUI_INT_OR:
			case CPUI_INT_LEFT:
			case CPUI_INT_RIGHT:
			case CPUI_INT_SRIGHT:
			case CPUI_INT_SUB:
			case CPUI_INT_ADD:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << ",";
					switch(iter->type)
					{
						case CPUI_INT_MULT: ss << "*"; break;
						// If divide by zero happen, give out 0
						case CPUI_INT_DIV: ss << "SWAP,DUP,!,?{,1,|,SWAP,0,&,},/"; break;
						case CPUI_INT_REM: ss << "SWAP,DUP,!,?{,1,|,SWAP,0,&,},%"; break;
						case CPUI_INT_SDIV: ss << "SIGN,SWAP,SIGN,DUP,!,?{,1,|,SWAP,0,&,},/"; break;
						case CPUI_INT_SREM: ss << "SIGN,SWAP,SIGN,DUP,!,?{,1,|,SWAP,0,&,},%"; break;
						case CPUI_INT_SUB: ss << "-"; break;
						case CPUI_INT_ADD: ss << "+"; break;
						case CPUI_BOOL_XOR:
						case CPUI_INT_XOR: ss << "^"; break;
						case CPUI_BOOL_AND:
						case CPUI_INT_AND: ss << "&"; break;
						case CPUI_BOOL_OR:
						case CPUI_INT_OR: ss << "|"; break;
						case CPUI_INT_LEFT: ss << "<<"; break;
						case CPUI_INT_RIGHT: ss << ">>"; break;
						case CPUI_INT_SRIGHT:
							ss << iter->input0->size * 8 << ",SWAP,SIGN,>>";
							break;
					}
					ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,&";

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_INT_CARRY:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << ",";
					if(!print_if_unique(iter->input1, 1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << ",+," << iter->input0->size * 8 << ",1,<<,1,SWAP,-,&";

					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << ",>";

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_INT_SCARRY:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",DUP,";
					if(!print_if_unique(iter->input1, 2))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^,1,^,SWAP";

					ss << ",";
					if(!print_if_unique(iter->input0, 2))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << ",";
					if(!print_if_unique(iter->input1, 3))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << ",+," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&"; // (a^b^1), a, c

					ss << ",^,&";

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_INT_SBORROW:
			{
				if(iter->input0 && iter->input1 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << ",-," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",DUP,";
					if(!print_if_unique(iter->input1, 2))
						ss << *iter->input1 << (iter->input1->is_reg()? ",GET": "");
					ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^,1,^,SWAP";

					ss << ",";
					if(!print_if_unique(iter->input0, 2))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");
					ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&"; // (r^b^1), a, r

					ss << ",^,&";

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_BOOL_NEGATE:
			case CPUI_INT_NEGATE:
			case CPUI_INT_2COMP:
			{
				if(iter->input0 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");

					if(iter->type == CPUI_BOOL_NEGATE)
						ss << ",!";
					else
					{
						ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,^";
						ss << ((iter->type == CPUI_INT_2COMP)? ",1,+": "");
					}

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_POPCOUNT:
			case CPUI_FLOAT_NAN:
			case CPUI_FLOAT_INT2FLOAT:
			case CPUI_FLOAT_FLOAT2FLOAT:
			case CPUI_FLOAT_TRUNC:
			case CPUI_FLOAT_CEIL:
			case CPUI_FLOAT_FLOOR:
			case CPUI_FLOAT_ROUND:
			case CPUI_FLOAT_SQRT:
			case CPUI_FLOAT_ABS:
			case CPUI_FLOAT_NEG:
			{
				if(iter->input0 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",GET": "");

					switch(iter->type)
					{
						case CPUI_POPCOUNT: ss << ",POPCOUNT"; break;
						case CPUI_FLOAT_NAN: ss << ",NAN"; break;
						case CPUI_FLOAT_TRUNC:
							ss << ",F2I," << iter->output->size * 8 << ",1,<<,1,SWAP,-,&";
							break;
						case CPUI_FLOAT_INT2FLOAT: ss << ",I2F"; break;
						case CPUI_FLOAT_CEIL: ss << ",CEIL"; break;
						case CPUI_FLOAT_FLOOR: ss << ",FLOOR"; break;
						case CPUI_FLOAT_ROUND: ss << ",ROUND"; break;
						case CPUI_FLOAT_SQRT: ss << ",SQRT"; break;
						case CPUI_FLOAT_ABS: ss << ",0,I2F,F<=,!,?{,-F,}"; break;
						case CPUI_FLOAT_NEG: ss << ",-F"; break;
						case CPUI_FLOAT_FLOAT2FLOAT: /* same as below */ break;
					}
					switch(iter->type)
					{
						case CPUI_FLOAT_INT2FLOAT:
						case CPUI_FLOAT_CEIL:
						case CPUI_FLOAT_FLOOR:
						case CPUI_FLOAT_ROUND:
						case CPUI_FLOAT_SQRT:
						case CPUI_FLOAT_ABS:
						case CPUI_FLOAT_NEG:
						case CPUI_FLOAT_FLOAT2FLOAT:
							ss << "," << iter->output->size * 8 << ",SWAP,F2F";
							break;
					}

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
					break;
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}
		}
	}

	if(!esil_stack.empty())
		ss << ",CLEAR";
	// std::cerr << hex << anal_op->addr << " " << ss.str() << endl;
	esilprintf(anal_op, ss.str()[0] == ','? ss.str().c_str() + 1: ss.str().c_str());
}

static bool anal_type_NOP(const std::vector<Pcodeop> &Pcodes)
{ // All p-codes have no side affects.
	for(auto iter = Pcodes.cbegin(); iter != Pcodes.cend(); ++iter)
	{
		if(iter->type == CPUI_STORE)
			return false;

		if(iter->output && !iter->output->is_unique())
			return false;
	}

	return true;
}

static int sleigh_op(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len,
                     RAnalOpMask mask)
{
	anal_op->addr = addr;
	anal_op->sign = true;
	anal_op->type = R_ANAL_OP_TYPE_ILL;

	PcodeSlg pcode_slg(&sanal);
	InnerAssemblyEmit assem;
	Address caddr(sanal.trans.getDefaultCodeSpace(), addr);
	anal_op->size = sanal.genOpcode(pcode_slg, caddr);
	if((anal_op->size < 1) || (sanal.trans.printAssembly(assem, caddr) < 1))
		return anal_op->size; // When current place has no available code, return ILL.

	if(pcode_slg.pcodes.empty())
	{ // NOP case
		anal_op->type = R_ANAL_OP_TYPE_NOP;
		esilprintf(anal_op, "");
		return anal_op->size;
	}

	SleighInstruction &ins = *sanal.trans.getInstruction(caddr);
	FlowType ftype = ins.getFlowType();
	bool isRefed = false;

	// std::cerr << caddr << " " << ins.printFlowType(ftype) << std::endl;
	if(ftype != FlowType::FALL_THROUGH)
	{
		switch(ftype)
		{
			case FlowType::TERMINATOR:
				// Stack info could be added
				anal_op->type = R_ANAL_OP_TYPE_RET;
				anal_op->eob = true;
				break;

			case FlowType::CONDITIONAL_TERMINATOR:
				anal_op->type = R_ANAL_OP_TYPE_CRET;
				anal_op->fail = ins.getFallThrough().getOffset();
				anal_op->eob = true;
				break;

			case FlowType::JUMP_TERMINATOR: anal_op->eob = true;
			case FlowType::UNCONDITIONAL_JUMP:
				anal_op->type = R_ANAL_OP_TYPE_JMP;
				anal_op->jump = ins.getFlows().begin()->getOffset();
				break;

			case FlowType::COMPUTED_JUMP:
			{
				char *reg = getIndirectReg(ins, isRefed);
				if(reg)
				{
					if(isRefed)
					{
						anal_op->type = R_ANAL_OP_TYPE_MJMP;
						anal_op->ireg = reg;
					}
					else
					{
						anal_op->type = R_ANAL_OP_TYPE_IRJMP;
						anal_op->reg = reg;
					}
				}
				else
					anal_op->type = R_ANAL_OP_TYPE_IJMP;
				break;
			}

			case FlowType::CONDITIONAL_COMPUTED_JUMP:
			{
				char *reg = getIndirectReg(ins, isRefed);
				if(reg)
				{
					if(isRefed)
					{
						anal_op->type = R_ANAL_OP_TYPE_MCJMP;
						anal_op->ireg = reg;
					}
					else
					{
						anal_op->type = R_ANAL_OP_TYPE_RCJMP;
						anal_op->reg = reg;
					}
				}
				else
					anal_op->type = R_ANAL_OP_TYPE_UCJMP;
				anal_op->fail = ins.getFallThrough().getOffset();
				break;
			}

			case FlowType::CONDITIONAL_JUMP:
				anal_op->type = R_ANAL_OP_TYPE_CJMP;
				anal_op->jump = ins.getFlows().begin()->getOffset();
				anal_op->fail = ins.getFallThrough().getOffset();
				break;

			case FlowType::CALL_TERMINATOR: anal_op->eob = true;
			case FlowType::UNCONDITIONAL_CALL:
				anal_op->type = R_ANAL_OP_TYPE_CALL;
				anal_op->jump = ins.getFlows().begin()->getOffset();
				anal_op->fail = ins.getFallThrough().getOffset();
				break;

			case FlowType::CONDITIONAL_COMPUTED_CALL:
			{
				char *reg = getIndirectReg(ins, isRefed);
				if(reg)
					if(isRefed)
						anal_op->ireg = reg;
					else
						anal_op->reg = reg;

				anal_op->type = R_ANAL_OP_TYPE_UCCALL;
				anal_op->fail = ins.getFallThrough().getOffset();
				break;
			}

			case FlowType::CONDITIONAL_CALL:
				anal_op->type |= R_ANAL_OP_TYPE_CCALL;
				anal_op->jump = ins.getFlows().begin()->getOffset();
				anal_op->fail = ins.getFallThrough().getOffset();
				break;

			case FlowType::COMPUTED_CALL_TERMINATOR: anal_op->eob = true;
			case FlowType::COMPUTED_CALL:
			{
				char *reg = getIndirectReg(ins, isRefed);
				if(reg)
				{
					if(isRefed)
					{
						anal_op->type = R_ANAL_OP_TYPE_IRCALL;
						anal_op->ireg = reg;
					}
					else
					{
						anal_op->type = R_ANAL_OP_TYPE_IRCALL;
						anal_op->reg = reg;
					}
				}
				else
					anal_op->type = R_ANAL_OP_TYPE_ICALL;
				anal_op->fail = ins.getFallThrough().getOffset();
				break;
			}

			default: throw LowlevelError("Unexpected FlowType occured in sleigh_op.");
		}
	}
	else
	{
		anal_type(a, anal_op, pcode_slg, assem);
#if 0
		switch(anal_op->type)
		{
			case R_ANAL_OP_TYPE_IRCALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_IRCALL"; break;
			case R_ANAL_OP_TYPE_RET: std::cerr << caddr << ": R_ANAL_OP_TYPE_RET"; break;
			case R_ANAL_OP_TYPE_ABS: std::cerr << caddr << ": R_ANAL_OP_TYPE_ABS"; break;
			case R_ANAL_OP_TYPE_CRET: std::cerr << caddr << ": R_ANAL_OP_TYPE_CRET"; break;
			case R_ANAL_OP_TYPE_IJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_IJMP"; break;
			case R_ANAL_OP_TYPE_RPUSH: std::cerr << caddr << ": R_ANAL_OP_TYPE_RPUSH"; break;
			case R_ANAL_OP_TYPE_NOP: std::cerr << caddr << ": R_ANAL_OP_TYPE_NOP"; break;
			case R_ANAL_OP_TYPE_SAR: std::cerr << caddr << ": R_ANAL_OP_TYPE_SAR"; break;
			case R_ANAL_OP_TYPE_NOT: std::cerr << caddr << ": R_ANAL_OP_TYPE_NOT"; break;
			case R_ANAL_OP_TYPE_CALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_CALL"; break;
			case R_ANAL_OP_TYPE_UPUSH: std::cerr << caddr << ": R_ANAL_OP_TYPE_UPUSH"; break;
			case R_ANAL_OP_TYPE_LOAD: std::cerr << caddr << ": R_ANAL_OP_TYPE_LOAD"; break;
			case R_ANAL_OP_TYPE_XCHG: std::cerr << caddr << ": R_ANAL_OP_TYPE_XCHG"; break;
			case R_ANAL_OP_TYPE_RCJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_RCJMP"; break;
			case R_ANAL_OP_TYPE_CAST: std::cerr << caddr << ": R_ANAL_OP_TYPE_CAST"; break;
			case R_ANAL_OP_TYPE_UCJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_UCJMP"; break;
			case R_ANAL_OP_TYPE_MOV: std::cerr << caddr << ": R_ANAL_OP_TYPE_MOV"; break;
			case R_ANAL_OP_TYPE_OR: std::cerr << caddr << ": R_ANAL_OP_TYPE_OR"; break;
			case R_ANAL_OP_TYPE_SHR: std::cerr << caddr << ": R_ANAL_OP_TYPE_SHR"; break;
			case R_ANAL_OP_TYPE_XOR: std::cerr << caddr << ": R_ANAL_OP_TYPE_XOR"; break;
			case R_ANAL_OP_TYPE_SHL: std::cerr << caddr << ": R_ANAL_OP_TYPE_SHL"; break;
			case R_ANAL_OP_TYPE_JMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_JMP"; break;
			case R_ANAL_OP_TYPE_ILL: std::cerr << caddr << ": R_ANAL_OP_TYPE_ILL"; break;
			case R_ANAL_OP_TYPE_AND: std::cerr << caddr << ": R_ANAL_OP_TYPE_AND"; break;
			case R_ANAL_OP_TYPE_SUB: std::cerr << caddr << ": R_ANAL_OP_TYPE_SUB"; break;
			case R_ANAL_OP_TYPE_DIV: std::cerr << caddr << ": R_ANAL_OP_TYPE_DIV"; break;
			case R_ANAL_OP_TYPE_UNK: std::cerr << caddr << ": R_ANAL_OP_TYPE_UNK"; break;
			case R_ANAL_OP_TYPE_CJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_CJMP"; break;
			case R_ANAL_OP_TYPE_MCJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_MCJMP"; break;
			case R_ANAL_OP_TYPE_UCCALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_UCCALL"; break;
			case R_ANAL_OP_TYPE_MJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_MJMP"; break;
			case R_ANAL_OP_TYPE_NEW: std::cerr << caddr << ": R_ANAL_OP_TYPE_NEW"; break;
			case R_ANAL_OP_TYPE_IRJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_IRJMP"; break;
			case R_ANAL_OP_TYPE_ADD: std::cerr << caddr << ": R_ANAL_OP_TYPE_ADD"; break;
			case R_ANAL_OP_TYPE_POP: std::cerr << caddr << ": R_ANAL_OP_TYPE_POP"; break;
			case R_ANAL_OP_TYPE_MOD: std::cerr << caddr << ": R_ANAL_OP_TYPE_MOD"; break;
			case R_ANAL_OP_TYPE_STORE: std::cerr << caddr << ": R_ANAL_OP_TYPE_STORE"; break;
			case R_ANAL_OP_TYPE_NOR: std::cerr << caddr << ": R_ANAL_OP_TYPE_NOR"; break;
			case R_ANAL_OP_TYPE_ICALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_ICALL"; break;
			case R_ANAL_OP_TYPE_MUL: std::cerr << caddr << ": R_ANAL_OP_TYPE_MUL"; break;
		}
		if(anal_op->val && anal_op->val != -1)
			std::cerr << " val: " << anal_op->val << std::endl;
		else
		{
			if(anal_op->dst)
			{
				std::cerr << " dst: ";
				char *tmp = r_anal_value_to_string(anal_op->dst);
				std::cerr << tmp;
				r_mem_free(tmp);
			}
			if(anal_op->src[0])
			{
				std::cerr << " in0: ";
				char *tmp = r_anal_value_to_string(anal_op->src[0]);
				std::cerr << tmp;
				r_mem_free(tmp);
			}
			if(anal_op->src[1])
			{
				std::cerr << " in1: ";
				char *tmp = r_anal_value_to_string(anal_op->src[1]);
				std::cerr << tmp;
				r_mem_free(tmp);
			}
			std::cerr << std::endl;
		}
#endif
	}

	if(mask & R_ANAL_OP_MASK_ESIL)
		sleigh_esil(a, anal_op, addr, data, len, pcode_slg.pcodes);

	return anal_op->size;
}

/*
 * By 2020-05-24, there are 17 kinds of group of registers in SLEIGH.
 * I map them to r_reg.h's RRegisterType:
 * R_REG_TYPE_XMM:
 * R_REG_TYPE_SEG:
 * R_REG_TYPE_DRX: DEBUG
 * R_REG_TYPE_FPU: ST FPU
 * R_REG_TYPE_MMX: MMX
 * R_REG_TYPE_YMM: AVX VSX
 * R_REG_TYPE_FLG: FLAGS Flags
 * R_REG_TYPE_GPR: PC Cx DCR STATUS SVE CONTROL SPR SPR_UNNAMED Alt NEON
 */
static const char *r_reg_type_arr[] = {"PC",  "Cx",          "DCR", "STATUS", "SVE",   "CONTROL",
                                "SPR", "SPR_UNNAMED", "Alt", "NEON",   "FLAGS", "Flags",
                                "AVX", "MMX",         "ST",  "FPU",    "DEBUG", "VSX", nullptr};
static const char *r_reg_string_arr[] = {"gpr", "gpr", "gpr", "gpr", "gpr", "gpr",
                                  "gpr", "gpr", "gpr", "gpr", "flg", "flg",
                                  "ymm", "mmx", "fpu", "fpu", "drx", "ymm", nullptr};

static int get_reg_type(const std::string &name)
{
	auto p = sanal.reg_mapping.cbegin();
	for(; p != sanal.reg_mapping.cend() && p->second != name; ++p) {}
	if(p == sanal.reg_mapping.cend())
		throw LowlevelError("get_reg_type: reg doesn't exist.");

	const std::string &group = sanal.reg_group[p->first];

	if(group.empty())
		return R_REG_TYPE_GPR;

	for(size_t i = 0; r_reg_type_arr[i]; i++)
	{
		if(group == r_reg_type_arr[i])
		{
			const char *curr = r_reg_string_arr[i];
			switch(curr[0] | curr[1] << 8)
			{
				case 'g' | 'p' << 8: return R_REG_TYPE_GPR;
				case 'd' | 'r' << 8: return R_REG_TYPE_DRX;
				case 'f' | 'p' << 8: return R_REG_TYPE_FPU;
				case 'm' | 'm' << 8: return R_REG_TYPE_MMX;
				case 'x' | 'm' << 8: return R_REG_TYPE_XMM;
				case 'y' | 'm' << 8: return R_REG_TYPE_YMM;
				case 'f' | 'l' << 8: return R_REG_TYPE_FLG;
				case 's' | 'e' << 8: return R_REG_TYPE_SEG;
			}
		}
	}

	return -1;
}

static void append_hardcoded_regs(std::stringstream &buf, const std::string &arch, bool little,
                                  int bits)
{
	if(arch.size() < 3)
		throw LowlevelError("append_hardcoded_regs: Unexpected arch name.");

	switch(arch[0] | arch[1] << 8 | arch[2] << 16)
	{
		case ('A' | 'R' << 8 | 'M' << 16): // ARM
		case ('A' | 'A' << 8 | 'R' << 16): // AARCH64
			if(bits == 64)
				buf << "=SN\t" << "x16" << "\n" << "=BP\t" << "x29" << "\n";
			else
				buf << "=SN\t" << "r7" << "\n" << "=BP\t" << "r11" << "\n";
			break;

		// case ('a' | 'v' << 8 | 'r' << 16): // avr8
		case ('a' | 'v' << 8 | 'r' << 16): // avr32
			buf << "=BP\t" << "y" << "\n";
			break;

		case ('6' | '8' << 8 | '0' << 16): // 68000
			buf << "=BP\t" << "a6" << "\n";
			break;

		case ('R' | 'I' << 8 | 'S' << 16): // RISCV
			buf << "=BP\t" << "s0" << "\n";
			break;

		case ('M' | 'I' << 8 | 'P' << 16): // MIPS
			buf << "=SN\t" << "v0" << "\n" << "=BP\t" << "f30" << "\n";
			break;

		case ('D' | 'a' << 8 | 'l' << 16): // Dalvik
			buf << "=SN\t" << "v0" << "\n" << "=BP\t" << "bp" << "\n";
			break;

		case ('P' | 'o' << 8 | 'w' << 16): // PowerPC
			if(bits == 32)
				buf << "=SN\t" << "r3" << "\n" << "=BP\t" << "r31" << "\n";
			break;

		case ('x' | '8' << 8 | '6' << 16): // x86
			if(bits == 16)
				buf << "=SN\t" << "ah" << "\n" << "=BP\t" << "bp" << "\n";
			if(bits == 32)
				buf << "=SN\t" << "eax" << "\n" << "=BP\t" << "ebp" << "\n";
			if(bits == 64)
				buf << "=SN\t" << "rax" << "\n" << "=BP\t" << "rbp" << "\n";
			break;

		case ('s' | 'p' << 8 | 'a' << 16): // sparc
			buf << "=BP\t" << "fp" << "\n";
			break;

		case ('V' | '8' << 8 | '5' << 16): // V850
		// case ('6' | '8' << 8 | '0' << 16): // 6809
		// case ('6' | '8' << 8 | '0' << 16): // 6805
		// case ('P' | 'I' << 8 | 'C' << 16): // PIC-24H
		// case ('P' | 'I' << 8 | 'C' << 16): // PIC-24F
		// case ('P' | 'I' << 8 | 'C' << 16): // PIC-24E
		// case ('P' | 'I' << 8 | 'C' << 16): // PIC-18
		// case ('P' | 'I' << 8 | 'C' << 16): // PIC-17
		// case ('P' | 'I' << 8 | 'C' << 16): // PIC-16
		case ('P' | 'I' << 8 | 'C' << 16): // PIC-12
		// case ('d' | 's' << 8 | 'P' << 16): // dsPIC33F
		// case ('d' | 's' << 8 | 'P' << 16): // dsPIC33E
		// case ('d' | 's' << 8 | 'P' << 16): // dsPIC33C
		case ('d' | 's' << 8 | 'P' << 16): // dsPIC30F
		// case ('z' | '1' << 8 | '8' << 16): // z182
		case ('z' | '1' << 8 | '8' << 16): // z180
		// case ('T' | 'I' << 8 | '_' << 16): // TI_MSP430X
		case ('T' | 'I' << 8 | '_' << 16): // TI_MSP430
		case ('p' | 'a' << 8 | '-' << 16): // pa-risc
		case ('8' | '0' << 8 | '8' << 16): // 8085
		// case ('H' | 'C' << 8 | 'S' << 16): // HCS12
		case ('H' | 'C' << 8 | 'S' << 16): // HCS08
		// case ('H' | 'C' << 8 | '0' << 16): // HC08
		case ('H' | 'C' << 8 | '0' << 16): // HC05
		case ('6' | '5' << 8 | '0' << 16): // 6502
		// case ('S' | 'u' << 8 | 'p' << 16): // SuperH
		case ('S' | 'u' << 8 | 'p' << 16): // SuperH4
		case ('T' | 'o' << 8 | 'y' << 16): // Toy
		case ('C' | 'P' << 8 | '1' << 16): // CP1600
		case ('J' | 'V' << 8 | 'M' << 16): // JVM
		case ('t' | 'r' << 8 | 'i' << 16): // tricore
		case ('z' | '8' << 8 | '0' << 16): // z80
		case ('8' | '0' << 8 | '5' << 16): // 8051
		case ('8' | '0' << 8 | '2' << 16): // 80251
		case ('M' | 'o' << 8 | 'd' << 16): // Mode
		case ('C' | 'R' << 8 | '1' << 16): // CR16C
		case ('8' | '0' << 8 | '3' << 16): // 80390
		case ('D' | 'A' << 8 | 'T' << 16): // DATA
		case ('z' | '8' << 8 | '4' << 16): // z8401x
		case ('8' | '0' << 8 | '4' << 16): // 8048
		case ('M' | 'C' << 8 | 'S' << 16): // MCS96
		case ('M' | 'a' << 8 | 'n' << 16): // Management
			break;

		default:
			throw LowlevelError("append_hardcoded_regs: Impossible arch name.");
	}
}

static char *get_reg_profile(RAnal *anal)
{
	ut64 length = strlen(anal->cpu), z = 0;
	for(; z < length && anal->cpu[z] != ':'; ++z) {}
	if(z == length)
		return nullptr;

	sanal.init(anal->cpu, anal? anal->iob.io: nullptr, SleighAsm::getConfig(anal));

	auto reg_list = sanal.getRegs();
	std::stringstream buf;

	for(auto p = reg_list.begin(); p != reg_list.end(); p++)
	{
		const std::string &group = sanal.reg_group[p->name];
		if(group.empty())
		{
			buf << "gpr\t" << sanal.reg_mapping[p->name] << "\t." << p->size * 8 << "\t"
			    << p->offset << "\t"
			    << "0\n";
			continue;
		}

		for(size_t i = 0;; i++)
		{
			if(!r_reg_type_arr[i])
			{
				fprintf(stderr,
				        "anal_ghidra.cpp:get_reg_profile() -> Get unexpected Register group(%s) "
				        "from SLEIGH, abort.",
				        group.c_str());
				return nullptr;
			}

			if(group == r_reg_type_arr[i])
			{
				buf << r_reg_string_arr[i] << '\t';
				break;
			}
		}

		buf << sanal.reg_mapping[p->name] << "\t." << p->size * 8 << "\t" << p->offset << "\t"
		    << "0\n";
	}

	if(!sanal.pc_name.empty())
		buf << "=PC\t" << sanal.reg_mapping[sanal.pc_name] << '\n';
	if(!sanal.sp_name.empty())
		buf << "=SP\t" << sanal.reg_mapping[sanal.sp_name] << '\n';

	for(unsigned i = 0; i != sanal.arg_names.size() && i <= 9; ++i)
		buf << "=A" << i << '\t' << sanal.reg_mapping[sanal.arg_names[i]] << '\n';

	for(unsigned i = 0; i != sanal.ret_names.size() && i <= 3; ++i)
		buf << "=R" << i << '\t' << sanal.reg_mapping[sanal.ret_names[i]] << '\n';

	ut64 pp = 0;
	string arch = sanal.sleigh_id.substr(pp, sanal.sleigh_id.find(':', pp) - pp);
	pp = sanal.sleigh_id.find(':', pp) + 1;
	bool little = sanal.sleigh_id.substr(pp, sanal.sleigh_id.find(':', pp) - pp) == "LE";
	pp = sanal.sleigh_id.find(':', pp) + 1;
	int bits = std::stoi(sanal.sleigh_id.substr(pp, sanal.sleigh_id.find(':', pp) - pp));
	pp = sanal.sleigh_id.find(':', pp) + 1;

	append_hardcoded_regs(buf, arch, little, bits);

	const std::string &res = buf.str();
	// fprintf(stderr, "%s\n", res.c_str());
	return strdup(res.c_str());
}

#define ERR(x)              \
	if(esil->verbose)       \
	{                       \
		eprintf("%s\n", x); \
	}

constexpr int ESIL_PARM_FLOAT = 127; // Avoid conflict

static bool esil_pushnum_float(RAnalEsil *esil, long double num)
{
	char str[64];
	snprintf(str, sizeof(str) - 1, "%.*LeF", DECIMAL_DIG, num);
	return r_anal_esil_push(esil, str);
}

static int esil_get_parm_type_float(RAnalEsil *esil, const char *str)
{
	int len, i;

	if(!str || !(len = strlen(str)))
		return R_ANAL_ESIL_PARM_INVALID;

	if((str[len - 1] == 'F') && (str[1] == '.' || (str[2] == '.' && str[0] == '-')))
		return ESIL_PARM_FLOAT;
	if(!strcmp(str, "nanF") || !strcmp(str, "infF") || !strcmp(str, "-nanF") ||
	   !strcmp(str, "-infF"))
		return ESIL_PARM_FLOAT;

	return R_ANAL_ESIL_PARM_INVALID;
}

static long double esil_get_double(RReg *reg, RRegItem *item)
{
	RRegSet *regset;
	float vf = 0.0f;
	double vd = 0.0f;
	int off;
	long double ret = 0.0f;
	if(!reg || !item)
	{
		return 0LL;
	}
	off = BITS2BYTES(item->offset);
	regset = &reg->regset[item->arena];
	switch(item->size)
	{
		case 32:
			if(regset->arena->size - off - 1 >= 0)
			{
				memcpy(&vf, regset->arena->bytes + off, sizeof(float));
				ret = vf;
			}
			break;
		case 64:
			if(regset->arena->size - off - 1 >= 0)
			{
				memcpy(&vd, regset->arena->bytes + off, sizeof(double));
				ret = vd;
			}
			break;
		case 80:
		case 96:
		case 128:
			if(regset->arena->size - off - 1 >= 0)
			{
				memcpy(&ret, regset->arena->bytes + off, sizeof(long double));
			}
			break;
		default:
			eprintf("esil_get_double: Bit size not supported.\n");
			return 0.0f;
	}
	return ret;
}

static bool esil_set_double(RReg *reg, RRegItem *item, long double value)
{
	ut8 *src;
	float vf = value;
	double vd = value;

	if(!item)
	{
		eprintf("esil_set_double: item is NULL.");
		return false;
	}
	switch(item->size)
	{
		case 32: src = (ut8 *)&vf;
		case 64: src = (ut8 *)&vd;
		case 80:
		case 96:
		case 128:
			// FIXME: endian
			src = (ut8 *)&value;
			break;
		default:
			eprintf("esil_set_double: Bit size not supported.");
			return false;
	}
	if(reg->regset[item->arena].arena->size - BITS2BYTES(item->offset) - BITS2BYTES(item->size) >=
	   0)
	{
		r_mem_copybits(reg->regset[item->arena].arena->bytes + BITS2BYTES(item->offset), src,
		               item->size);
		return true;
	}
	eprintf("esil_set_double: Cannot set register.");
	return false;
}

static int esil_get_parm_float(RAnalEsil *esil, const char *str, long double *num)
{
	int ret = 0;
	if(!str || !*str)
		return false;

	if(!num || !esil)
		return false;

	if(!strcmp("0x0", str) || !strcmp("0", str))
	{
		*num = 0.0;
		return true;
	}

	int parm_type = esil_get_parm_type_float(esil, str);
	switch(parm_type)
	{
		case ESIL_PARM_FLOAT:
			// *num = r_num_get (NULL, str);
			sscanf(str, "%LfF", num);
			ret = 1;
			break;
		case R_ANAL_ESIL_PARM_REG:
		{
			RRegItem *reg = r_reg_get(esil->anal->reg, str, get_reg_type(str));
			if(reg)
			{
				*num = esil_get_double(esil->anal->reg, reg);
				ret = 1;
			}
			break;
		}
		default:
			ERR("esil_get_parm_float: Invalid arg.");

			esil->parse_stop = 1;
			break;
	}
	return ret;
}

static bool sleigh_esil_consts_pick(RAnalEsil *esil)
{
	if(!esil || !esil->stack)
		return false;

	char *idx = r_anal_esil_pop(esil);
	ut64 i;
	int ret = false;

	if(R_ANAL_ESIL_PARM_REG == r_anal_esil_get_parm_type(esil, idx))
	{
		ERR("sleigh_esil_consts_pick: argument is consts only.");
		goto end;
	}
	if(!idx || !r_anal_esil_get_parm(esil, idx, &i))
	{
		ERR("esil_pick: invalid index number.");
		goto end;
	}
	if(esil->stackptr < i)
	{
		ERR("esil_pick: index out of stack bounds.");
		goto end;
	}
	if(!esil->stack[esil->stackptr - i])
	{
		ERR("esil_pick: undefined element.");
		goto end;
	}
	if(!r_anal_esil_push(esil, esil->stack[esil->stackptr - i]))
	{
		ERR("ESIL stack is full.");
		esil->trap = 1;
		esil->trap_code = 1;
		goto end;
	}
	ret = true;

end:
	r_mem_free(idx);
	return ret;
}

static bool sleigh_esil_is_nan(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
			ret = r_anal_esil_pushnum(esil, isnan(s));
		else
			ERR("sleigh_esil_is_nan: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_is_nan: fail to get argument from stack.");

	return ret;
}

static bool sleigh_esil_int_to_float(RAnalEsil *esil)
{
	bool ret = false;
	st64 s;
	char *src = r_anal_esil_pop(esil);
	if(src)
	{
		if(r_anal_esil_get_parm(esil, src, (ut64 *)&s))
			ret = esil_pushnum_float(esil, (long double)s * 1.0);
		else
			ERR("sleigh_esil_int_to_float: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_int_to_float: fail to get argument from stack.");

	return ret;
}

static bool sleigh_esil_float_to_int(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
		{
			if(isnan(s) || isinf(s))
				ERR("sleigh_esil_float_to_int: nan or inf detected.");
			ret = r_anal_esil_pushnum(esil, (st64)(s));
		}
		else
			ERR("sleigh_esil_float_to_int: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_to_int: fail to get argument from stack.");

	return ret;
}

static bool sleigh_esil_float_to_float(RAnalEsil *esil)
{
	bool ret = false;
	long double d;
	ut64 s = 0;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_to_float: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_to_float: fail to get argument from stack.");
		goto end2;
	}

	if(r_anal_esil_get_parm(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(d) || isinf(d))
			ret = esil_pushnum_float(esil, d);
		else if(s == 4)
			ret = esil_pushnum_float(esil, (float)d);
		else if(s == 8)
			ret = esil_pushnum_float(esil, (double)d);
		else
			ret = esil_pushnum_float(esil, d);
			/* This is wrong. We should make a full-functional class to emulate FP.
			throw LowlevelError(
			    "sleigh_esil_float_to_float: byte-width of float number overflows.");
			*/
	}
	else
		ERR("sleigh_esil_float_to_float: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_cmp(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_cmp: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_cmp: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, fabs(s - d) < std::numeric_limits<long double>::epsilon());
	}
	else
		ERR("sleigh_esil_float_cmp: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_cmp(RAnalEsil *esil)
{
	ut64 num, num2;
	bool ret = false;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_cmp: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_cmp: fail to get argument from stack.");
		goto end2;
	}

	if(r_anal_esil_get_parm(esil, dst, &num) && r_anal_esil_get_parm(esil, src, &num2))
	{
		esil->old = num;
		esil->cur = num - num2;
		ret = true;
		esil->lastsz = 64;
		r_anal_esil_pushnum(esil, num == num2);
	}
	else
		ERR("sleigh_esil_cmp: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_negcmp(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_negcmp: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_negcmp: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, fabs(s - d) >= std::numeric_limits<long double>::epsilon());
	}
	else
		ERR("sleigh_esil_float_negcmp: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_less(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_less: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_less: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, s < d);
	}
	else
		ERR("sleigh_esil_float_less: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_lesseq(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_lesseq: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_lesseq: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, s <= d);
	}
	else
		ERR("sleigh_esil_float_lesseq: invalid parameters.");


end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_add(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_add: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_add: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, s);
		else if(isnan(d))
			ret = esil_pushnum_float(esil, d);
		else
		{
			feclearexcept(FE_OVERFLOW);
			long double tmp = s + d;
			auto raised = fetestexcept(FE_OVERFLOW);
			if(raised & FE_OVERFLOW)
				ret = esil_pushnum_float(esil, 0.0 / 0.0);
			else
				ret = esil_pushnum_float(esil, s + d);
		}
	}
	else
		ERR("sleigh_esil_float_add: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_sub(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_sub: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_sub: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, s);
		else if(isnan(d))
			ret = esil_pushnum_float(esil, d);
		else
		{
			feclearexcept(FE_OVERFLOW);
			long double tmp = d - s;
			auto raised = fetestexcept(FE_OVERFLOW);
			if(raised & FE_OVERFLOW)
				ret = esil_pushnum_float(esil, 0.0 / 0.0);
			else
				ret = esil_pushnum_float(esil, d - s);
		}
	}
	else
		ERR("sleigh_esil_float_sub: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_mul(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_mul: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_mul: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, s);
		else if(isnan(d))
			ret = esil_pushnum_float(esil, d);
		else
		{
			feclearexcept(FE_OVERFLOW);
			long double tmp = s * d;
			auto raised = fetestexcept(FE_OVERFLOW);
			if(raised & FE_OVERFLOW)
				ret = esil_pushnum_float(esil, 0.0 / 0.0);
			else
				ret = esil_pushnum_float(esil, s * d);
		}
	}
	else
		ERR("sleigh_esil_float_mul: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_div(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if(!src)
	{
		ERR("sleigh_esil_float_div: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_float_div: fail to get argument from stack.");
		goto end2;
	}

	if(esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, s);
		else if(isnan(d))
			ret = esil_pushnum_float(esil, d);
		else
		{
			feclearexcept(FE_OVERFLOW);
			long double tmp = d / s;
			auto raised = fetestexcept(FE_OVERFLOW);
			if(raised & FE_OVERFLOW)
				ret = esil_pushnum_float(esil, 0.0 / 0.0);
			else
				ret = esil_pushnum_float(esil, d / s);
		}
	}
	else
		ERR("sleigh_esil_float_div: invalid parameters.");

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_neg(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);

	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
			ret = esil_pushnum_float(esil, -s);
		else
			ERR("sleigh_esil_float_neg: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_neg: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_ceil(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);

	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
		{
			if(isnan(s))
				ret = esil_pushnum_float(esil, s);
			else
				ret = esil_pushnum_float(esil, std::ceil(s));
		}
		else
			ERR("sleigh_esil_float_ceil: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_ceil: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_floor(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);

	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
		{
			if(isnan(s))
				ret = esil_pushnum_float(esil, s);
			else
				ret = esil_pushnum_float(esil, std::floor(s));
		}
		else
			ERR("sleigh_esil_float_floor: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_floor: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_round(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);

	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
		{
			if(isnan(s))
				ret = esil_pushnum_float(esil, s);
			else
				ret = esil_pushnum_float(esil, std::round(s));
		}
		else
			ERR("sleigh_esil_float_round: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_round: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_sqrt(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);

	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
		{
			if(isnan(s))
				ret = esil_pushnum_float(esil, s);
			else
				ret = esil_pushnum_float(esil, std::sqrt(s));
		}
		else
			ERR("sleigh_esil_float_sqrt: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_sqrt: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_popcount(RAnalEsil *esil)
{
	bool ret = false;
	ut64 s, res = 0;
	char *src = r_anal_esil_pop(esil);

	if(src)
	{
		if(src && r_anal_esil_get_parm(esil, src, &s))
		{
			while(s)
			{
				s &= s - 1;
				++res;
			}
			ret = r_anal_esil_pushnum(esil, res);
		}
		else
			ERR("sleigh_esil_popcount: invalid parameters.");

		r_mem_free(src);
	}
	else
		ERR("sleigh_esil_popcount: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_signext(RAnalEsil *esil)
{
	// From https://github.com/radareorg/radare2/pull/17436/
	ut64 src, dst;

	char *p_src = r_anal_esil_pop(esil);
	if(!p_src)
		return false;

	if(!r_anal_esil_get_parm(esil, p_src, &src))
	{
		ERR("sleigh_esil_signext: invalid parameters.");
		r_mem_free(p_src);
		return false;
	}
	else
		r_mem_free(p_src);

	char *p_dst = r_anal_esil_pop(esil);
	if(!p_dst)
		return false;

	if(!r_anal_esil_get_parm(esil, p_dst, &dst))
	{
		ERR("sleigh_esil_signext: invalid parameters.");
		r_mem_free(p_dst);
		return false;
	}
	else
		r_mem_free(p_dst);

	ut64 m = 0;
	if(dst < 64)
		m = 1ULL << (dst - 1);

	// dst = (dst & ((1U << src_bit) - 1)); // clear upper bits
	return r_anal_esil_pushnum(esil, ((src ^ m) - m));
}

static void sleigh_reg_set_float(RReg *reg, const char *name, int type, bool F)
{
	RRegItem *tmp = r_reg_get(reg, name, type);
	tmp->is_float = F;
}

static bool sleigh_reg_get_float(RReg *reg, const char *name, int type)
{
	RRegItem *tmp = r_reg_get(reg, name, type);
	return tmp->is_float;
}

// All register's value will be resolved immediately thanks to GET.
static bool sleigh_esil_reg_get(RAnalEsil *esil)
{
	// When register name is just a single char,
	// ESIL vm will only replace it with its value
	// when calculation is applied on that register.
	// But if you just compare it with another value,
	// ESIL vm will compare its name with that value.
	// So I will replace every register with this op,
	// when a register is pushed on ESIL stack.
	bool is_float = false;
	bool ret = false;
	if(!esil || !esil->stack)
		return false;
	if(!esil->anal || !esil->anal->reg)
		return false;

	char *name = r_anal_esil_pop(esil);
	ut64 i;

	if(name)
	{
		if(R_ANAL_ESIL_PARM_REG != r_anal_esil_get_parm_type(esil, name))
			ERR("sleigh_esil_reg_get: stack top isn't register.");

		is_float = sleigh_reg_get_float(esil->anal->reg, name, get_reg_type(name));
		if(is_float)
		{
			RRegItem *reg = r_reg_get(esil->anal->reg, name, get_reg_type(name));
			long double res = esil_get_double(esil->anal->reg, reg);
			ret = esil_pushnum_float(esil, res);
		}
		else
		{
			r_anal_esil_get_parm(esil, name, &i);
			ret = r_anal_esil_pushnum(esil, i);
		}

		r_mem_free(name);
	}
	else
		ERR("sleigh_esil_reg_get: fail to get element from stack.");

	return ret;
}

static bool isnum(RAnalEsil *esil, const char *str, ut64 *num)
{
	if(!esil || !str)
	{
		return false;
	}
	if(IS_DIGIT(*str))
	{
		if(num)
		{
			*num = r_num_get(NULL, str);
		}
		return true;
	}
	if(num)
	{
		*num = 0;
	}
	return false;
}

static bool ispackedreg(RAnalEsil *esil, const char *str)
{
	RRegItem *ri = r_reg_get(esil->anal->reg, str, -1);
	return ri? ri->packed_size > 0: false;
}

static bool isregornum(RAnalEsil *esil, const char *str, ut64 *num)
{
	if(!r_anal_esil_reg_read(esil, str, num, NULL))
	{
		if(!isnum(esil, str, num))
		{
			return false;
		}
	}
	return true;
}

static inline ut64 genmask(int bits)
{
	ut64 m = UT64_MAX;
	if(bits > 0 && bits < 64)
	{
		m = (ut64)(((ut64)(2) << bits) - 1);
		if(!m)
		{
			m = UT64_MAX;
		}
	}
	return m;
}

static ut8 esil_internal_sizeof_reg(RAnalEsil *esil, const char *r)
{
	r_return_val_if_fail(esil && esil->anal && esil->anal->reg && r, 0);
	RRegItem *ri = r_reg_get(esil->anal->reg, r, -1);
	return ri? ri->size: 0;
}

static int r_anal_esil_reg_read_nocallback(RAnalEsil *esil, const char *regname, ut64 *num,
                                           int *size)
{
	int ret;
	int (*old_hook_reg_read)(r_anal_esil_t *, const char *, long long unsigned int *, int *) =
	    esil->cb.hook_reg_read;
	esil->cb.hook_reg_read = NULL;
	ret = r_anal_esil_reg_read(esil, regname, num, size);
	esil->cb.hook_reg_read = old_hook_reg_read;
	return ret;
}

static bool esil_eq(RAnalEsil *esil)
{
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if(!src || !dst)
	{
		ERR("esil_eq: Missing elements in esil stack.");
		return false;
	}
	if(ispackedreg(esil, dst))
	{
		char *src2 = r_anal_esil_pop(esil);
		char *newreg = r_str_newf("%sl", dst);
		if(r_anal_esil_get_parm(esil, src2, &num2))
			ret = r_anal_esil_reg_write(esil, newreg, num2);

		r_mem_free(newreg);
		r_mem_free(src2);
		goto beach;
	}

	if(r_anal_esil_reg_read_nocallback(esil, dst, &num, NULL))
	{
		if(r_anal_esil_get_parm(esil, src, &num2))
		{
			ret = r_anal_esil_reg_write(esil, dst, num2);
			esil->cur = num2;
			esil->old = num;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
		}
		else
			ERR("esil_eq: invalid src.");
	}
	else
		ERR("esil_eq: invalid parameters.");

beach:
	r_mem_free(src);
	r_mem_free(dst);
	return ret;
}

static bool esil_peek_n(RAnalEsil *esil, int bits)
{
	if(bits & 7)
		return false;

	bool ret = false;
	char res[32];
	ut64 addr;
	ut32 bytes = bits / 8;
	char *dst = r_anal_esil_pop(esil);
	if(!dst)
	{
		ERR("esil_peek_n: Can't peek memory without an address.");
		return false;
	}
	// eprintf ("GONA PEEK %d dst:%s\n", bits, dst);
	if(dst && isregornum(esil, dst, &addr))
	{
		if(bits == 128)
		{
			ut8 a[sizeof(ut64) * 2] = {0};
			ret = r_anal_esil_mem_read(esil, addr, a, bytes);
			ut64 b = r_read_ble64(&a, 0);    // esil->anal->big_endian);
			ut64 c = r_read_ble64(&a[8], 0); // esil->anal->big_endian);
			snprintf(res, sizeof(res), "0x%" PFMT64x, b);
			r_anal_esil_push(esil, res);
			snprintf(res, sizeof(res), "0x%" PFMT64x, c);
			r_anal_esil_push(esil, res);
			r_mem_free(dst);
			return ret;
		}
		ut64 bitmask = genmask(bits - 1);
		ut8 a[sizeof(ut64)] = {0};
		ret = !!r_anal_esil_mem_read(esil, addr, a, bytes);
		ut64 b = r_read_ble64(a, 0); // esil->anal->big_endian);
		if(esil->anal->big_endian)
			r_mem_swapendian((ut8 *)&b, (const ut8 *)&b, bytes);

		snprintf(res, sizeof(res), "0x%" PFMT64x, b & bitmask);
		r_anal_esil_push(esil, res);
		esil->lastsz = bits;
	}
	r_mem_free(dst);
	return ret;
}

static bool esil_poke_n(RAnalEsil *esil, int bits)
{
	ut64 bitmask = genmask(bits - 1);
	ut64 num, num2, addr;
	ut8 b[8] = {0};
	ut64 n;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	int bytes = R_MIN(sizeof(b), bits / 8);
	if(bits % 8)
	{
		r_mem_free(src);
		r_mem_free(dst);
		return false;
	}
	bool ret = false;
	// eprintf ("GONA POKE %d src:%s dst:%s\n", bits, src, dst);
	char *src2 = NULL;
	if(src && r_anal_esil_get_parm(esil, src, &num))
	{
		if(dst && r_anal_esil_get_parm(esil, dst, &addr))
		{
			if(bits == 128)
			{
				src2 = r_anal_esil_pop(esil);
				if(src2 && r_anal_esil_get_parm(esil, src2, &num2))
				{
					r_write_ble(b, num, esil->anal->big_endian, 64);
					ret = r_anal_esil_mem_write(esil, addr, b, bytes);
					if(ret == 0)
					{
						r_write_ble(b, num2, esil->anal->big_endian, 64);
						ret = r_anal_esil_mem_write(esil, addr + 8, b, bytes);
					}
					goto out;
				}
				ret = -1;
				goto out;
			}
			// this is a internal peek performed before a poke
			// we disable hooks to avoid run hooks on internal peeks
			int (*oldhook)(r_anal_esil_t *, long long unsigned int, unsigned char *, int) =
			    esil->cb.hook_mem_read;
			esil->cb.hook_mem_read = NULL;
			r_anal_esil_mem_read(esil, addr, b, bytes);
			esil->cb.hook_mem_read = oldhook;
			n = r_read_ble64(b, esil->anal->big_endian);
			esil->old = n;
			esil->cur = num;
			esil->lastsz = bits;
			num = num & bitmask;
			r_write_ble(b, num, esil->anal->big_endian, bits);
			ret = r_anal_esil_mem_write(esil, addr, b, bytes);
		}
	}
out:
	r_mem_free(src2);
	r_mem_free(src);
	r_mem_free(dst);
	return ret;
}

static bool sleigh_esil_eq(RAnalEsil *esil)
{
	bool ret = false;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	long double tmp;

	if(!src)
	{
		ERR("sleigh_esil_eq: fail to get argument from stack.");
		return false;
	}
	if(!dst)
	{
		ERR("sleigh_esil_eq: fail to get argument from stack.");
		r_mem_free(src);
		return false;
	}

	RRegItem *reg = r_reg_get(esil->anal->reg, dst, get_reg_type(dst));
	if(ESIL_PARM_FLOAT == esil_get_parm_type_float(esil, src))
	{
		esil_get_parm_float(esil, src, &tmp);
		ret = esil_set_double(esil->anal->reg, reg, tmp);
		sleigh_reg_set_float(esil->anal->reg, dst, get_reg_type(dst), true);
	}
	else
	{
		r_anal_esil_push(esil, src);
		r_anal_esil_push(esil, dst);
		ret = esil_eq(esil);
		sleigh_reg_set_float(esil->anal->reg, dst, get_reg_type(dst), false);
	}

	r_mem_free(dst);
	r_mem_free(src);

	return ret;
}

static unordered_set<uintm> float_mem;

static bool sleigh_esil_peek4(RAnalEsil *esil) // Read out
{
	ut64 addr;
	char *src = r_anal_esil_pop(esil);
	bool ret = false;
	char str[64];

	if(!src)
	{
		ERR("sleigh_esil_peek4: fail to get element from stack.");
		return false;
	}

	if(!isnum(esil, src, &addr))
	{
		ERR("sleigh_esil_peek4: Can't get addr.");
		r_mem_free(src);
		return true;
	}

	if(float_mem.find(addr) != float_mem.end())
	{
		float a;
		ret = !!r_anal_esil_mem_read(esil, addr, (ut8 *)&a, 4);
		snprintf(str, sizeof(str) - 1, "%.*LeF", DECIMAL_DIG, (long double)a);
		r_anal_esil_push(esil, str);
		esil->lastsz = 32;
	}
	else
	{
		r_anal_esil_push(esil, src);
		ret = esil_peek_n(esil, 32);
	}

	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_peek8(RAnalEsil *esil)
{
	ut64 addr;
	char *src = r_anal_esil_pop(esil);
	bool ret = false;
	char str[64];

	if(!src)
	{
		ERR("sleigh_esil_peek8: fail to get element from stack.");
		return false;
	}

	if(!isnum(esil, src, &addr))
	{
		ERR("sleigh_esil_peek8: Can't get addr.");
		r_mem_free(src);
		return true;
	}

	if(float_mem.find(addr) != float_mem.end())
	{
		double a;
		ret = !!r_anal_esil_mem_read(esil, addr, (ut8 *)&a, 8);
		snprintf(str, sizeof(str) - 1, "%.*LeF", DECIMAL_DIG, (long double)a);
		r_anal_esil_push(esil, str);
		esil->lastsz = 64;
	}
	else
	{
		r_anal_esil_push(esil, src);
		ret = esil_peek_n(esil, 64);
	}

	r_mem_free(src);
	return ret;
}

static bool sleigh_esil_poke4(RAnalEsil *esil)
{
	bool ret = false;
	ut64 addr;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	long double tmp;

	if(!src)
	{
		ERR("sleigh_esil_poke4: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_poke4: fail to get argument from stack.");
		goto end2;
	}
	if(!isregornum(esil, dst, &addr))
	{
		ERR("sleigh_esil_poke4: Can't get addr.");
		goto end2;
	}

	if(ESIL_PARM_FLOAT == esil_get_parm_type_float(esil, src))
	{
		esil_get_parm_float(esil, src, &tmp);
		float res = tmp;
		esil->lastsz = 32;
		ret = r_anal_esil_mem_write(esil, addr, (ut8 *)&res, 4);
		float_mem.insert(addr);
	}
	else
	{
		r_anal_esil_push(esil, src);
		r_anal_esil_push(esil, dst);
		ret = esil_poke_n(esil, 32);
		auto iter = float_mem.find(addr);
		if(iter != float_mem.end())
			float_mem.erase(iter);
	}

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);

	return ret;
}

static bool sleigh_esil_poke8(RAnalEsil *esil)
{
	bool ret = false;
	ut64 addr;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	long double tmp;

	if(!src)
	{
		ERR("sleigh_esil_poke8: fail to get argument from stack.");
		goto end1;
	}
	if(!dst)
	{
		ERR("sleigh_esil_poke8: fail to get argument from stack.");
		goto end2;
	}
	if(!isregornum(esil, dst, &addr))
	{
		ERR("sleigh_esil_poke8: Can't get addr.");
		goto end2;
	}

	if(ESIL_PARM_FLOAT == esil_get_parm_type_float(esil, src))
	{
		esil_get_parm_float(esil, src, &tmp);
		double res = tmp;
		esil->lastsz = 64;
		ret = r_anal_esil_mem_write(esil, addr, (ut8 *)&res, 8);
		float_mem.insert(addr);
	}
	else
	{
		r_anal_esil_push(esil, src);
		r_anal_esil_push(esil, dst);
		ret = esil_poke_n(esil, 64);
		auto iter = float_mem.find(addr);
		if(iter != float_mem.end())
			float_mem.erase(iter);
	}

end2:
	r_mem_free(dst);
end1:
	r_mem_free(src);

	return ret;
}

static int esil_sleigh_init(RAnalEsil *esil)
{
	if(!esil)
		return false;

	float_mem.clear();

	// Only consts-only version PICK will meet my demand
	r_anal_esil_set_op(esil, "PICK", sleigh_esil_consts_pick, 1, 0, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	// Reg -> Stack
	r_anal_esil_set_op(esil, "GET", sleigh_esil_reg_get, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "NAN", sleigh_esil_is_nan, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	// Stack -> Reg
	r_anal_esil_set_op(esil, "=", sleigh_esil_eq, 0, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "I2F", sleigh_esil_int_to_float, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F2I", sleigh_esil_float_to_int, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F2F", sleigh_esil_float_to_float, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	// Stack -> Mem
	r_anal_esil_set_op(esil, "=[4]", sleigh_esil_poke4, 0, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "=[8]", sleigh_esil_poke8, 0, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	// Mem -> Stack
	r_anal_esil_set_op(esil, "[4]", sleigh_esil_peek4, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "[8]", sleigh_esil_peek8, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F==", sleigh_esil_float_cmp, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "==", sleigh_esil_cmp, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F!=", sleigh_esil_float_negcmp, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F<", sleigh_esil_float_less, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F<=", sleigh_esil_float_lesseq, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F+", sleigh_esil_float_add, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F-", sleigh_esil_float_sub, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F*", sleigh_esil_float_mul, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F/", sleigh_esil_float_div, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "-F", sleigh_esil_float_neg, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "CEIL", sleigh_esil_float_ceil, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "FLOOR", sleigh_esil_float_floor, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "ROUND", sleigh_esil_float_round, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "SQRT", sleigh_esil_float_sqrt, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "SIGN", sleigh_esil_signext, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "POPCOUNT", sleigh_esil_popcount, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);

	return true;
}

static int esil_sleigh_fini(RAnalEsil *esil)
{
	float_mem.clear();
	return true;
}

RAnalPlugin r_anal_plugin_ghidra = {
	/* .name = */ "r2ghidra",
	/* .desc = */ "SLEIGH Disassembler from Ghidra",
	/* .license = */ "GPL3",
	/* .arch = */ "sleigh",
	/* .author = */ "FXTi",
	/* .version = */ nullptr,
	/* .bits = */ 0,
	/* .esil = */ true,
	/* .fileformat_type = */ 0,
	/* .init = */ nullptr,
	/* .fini = */ nullptr,
	/* .archinfo = */ &archinfo,
	/* .anal_mask = */ nullptr,
	/* .preludes = */ nullptr,
	/* .op = */ &sleigh_op,
	/* .cmd_ext = */ nullptr,
	/* .set_reg_profile = */ nullptr,
	/* .get_reg_profile = */ &get_reg_profile,
	/* .fingerprint_bb = */ nullptr,
	/* .fingerprint_fcn = */ nullptr,
	/* .diff_bb = */ nullptr,
	/* .diff_fcn = */ nullptr,
	/* .diff_eval = */ nullptr,
	/* .esil_init = */ esil_sleigh_init,
	/* .esil_post_loop = */ nullptr,
	/* .esil_trap = */ nullptr,
	/* .esil_fini = */ esil_sleigh_fini,
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_ANAL,
	/* .data = */ &r_anal_plugin_ghidra,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr
#if R2_VERSION_MAJOR >= 4 && R2_VERSION_MINOR >= 2
	, "r2ghidra-dec"
#endif
};
#endif
