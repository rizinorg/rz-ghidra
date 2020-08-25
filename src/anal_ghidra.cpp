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
	if(!strcmp(anal->cpu, "x86"))
		return -1;

	sanal.init(anal);
	if(query == R_ANAL_ARCHINFO_ALIGN)
		return sanal.alignment;
	else
		return -1;
}

static std::vector<std::string> string_split(const std::string &s, const char &delim = ' ')
{
	std::vector<std::string> tokens;
	size_t lastPos = s.find_first_not_of(delim, 0);
	size_t pos = s.find(delim, lastPos);
	while(lastPos != string::npos)
	{
		tokens.emplace_back(s.substr(lastPos, pos - lastPos));
		lastPos = s.find_first_not_of(delim, pos);
		pos = s.find(delim, lastPos);
	}
	return tokens;
}

static std::string string_trim(std::string s)
{
	if(!s.empty())
	{
		s.erase(0, s.find_first_not_of(" "));
		s.erase(s.find_last_not_of(" ") + 1);
	}
	return s;
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

static bool isOperandInteresting(const PcodeOperand *arg, std::unordered_set<std::string> &regs,
                                 std::unordered_set<PcodeOperand, PcodeOperand> &mid_vars)
{
	if(arg)
	{
		if(arg->is_reg())
			return regs.find(arg->name) != regs.end();

		if(arg->is_unique())
			return mid_vars.find(*arg) != mid_vars.end();
	}
	return false;
}

template<typename T>
static inline T inner_max(T foo, T bar)
{
	return foo > bar ? foo : bar;
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
			if(in0.absolute == -1) return in0;
		}
		if(curr_op->input1)
		{
			in1 = resolve_arg(anal, curr_op->input1);
			if(in1.absolute == -1) return in1;
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
					res.reg = in0.reg ? in0.reg : in1.reg;
					res.regdelta = in0.regdelta ? in0.regdelta : in1.regdelta;
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
					res.reg = in0.reg ? in0.reg : in1.reg;
					res.regdelta = in0.regdelta ? in0.regdelta : in1.regdelta;
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

			default:
				res.absolute = -1; // Means invalid
		}
	}

	return res;
}

static std::vector<RAnalValue>
    resolve_out(RAnal *anal, std::vector<Pcodeop>::const_iterator curr_op,
                std::vector<Pcodeop>::const_iterator end_op, const PcodeOperand *arg)
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
						tmp.reg = r_reg_get(anal->reg, iter->output->name.c_str(), get_reg_type(iter->output->name));
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

				if(iter->type == key_pcode_load ? iter->input1 : iter->input0)
					in0 = resolve_arg(anal, iter->type == key_pcode_load ? iter->input1 : iter->input0);

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

			anal_op->type = has_cbranch ? R_ANAL_OP_TYPE_CSWI : R_ANAL_OP_TYPE_SWI;

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
				out = resolve_arg(anal, iter->input1);

			if((out.reg && sanal.sp_name == out.reg->name) ||
			   (out.regdelta && sanal.sp_name == out.regdelta->name))
			{
				anal_op->type = R_ANAL_OP_TYPE_UPUSH;
				anal_op->stackop = R_ANAL_STACK_INC;

				if(iter->output)
					in = resolve_arg(anal, iter->output);

				if(arg_set_has(arg_set, in))
					anal_op->type = R_ANAL_OP_TYPE_RPUSH;

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

			if((in0.reg && sanal.sp_name == in0.reg->name) ||
			   (in0.regdelta && sanal.sp_name == in0.regdelta->name))
			{
				if(iter->output)
					outs = resolve_out(anal, iter, raw_ops.cend(), iter->output);

				auto p = outs.cbegin();
				for(; p != outs.cend() && !arg_set_has(arg_set, *p); ++p) {}
				if(p == outs.cend())
					continue;

				anal_op->type = this_type;
				anal_op->stackop = R_ANAL_STACK_INC;

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
			if(!arg_set_has(arg_set, in0))
				continue;

			if(iter->input1)
				in1 = resolve_arg(anal, iter->input1);
			if(!arg_set_has(arg_set, in1))
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

			anal_op->type = key_pcode == key_pcode_sub ? R_ANAL_OP_TYPE_CMP : R_ANAL_OP_TYPE_ACMP;
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

	if(raw_ops.size() == 3 && raw_ops[0].type == raw_ops[1].type &&
	   raw_ops[1].type == raw_ops[2].type && raw_ops[2].type == key_pcode)
	{
		if(!raw_ops[0].input0 || !raw_ops[0].output)
			return 0;
		if(!raw_ops[1].input0 || !raw_ops[1].output)
			return 0;
		if(!raw_ops[2].input0 || !raw_ops[2].output)
			return 0;

		if(*raw_ops[0].input0 == *raw_ops[1].output && *raw_ops[0].output == *raw_ops[2].input0 &&
		   *raw_ops[1].input0 == *raw_ops[2].output)
		{
			anal_op->type = this_type;
			anal_op->src[0] = anal_value_dup(resolve_arg(anal, raw_ops[0].input0));
			anal_op->src[1] = anal_value_dup(resolve_arg(anal, raw_ops[1].input0));
			anal_op->dst = anal_value_dup(resolve_arg(anal, raw_ops[1].output));

			return this_type;
		}
	}

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
	std::vector<std::string> args = string_split(assem.args, ',');
	std::transform(args.begin(), args.end(), args.begin(), string_trim);
	std::unordered_set<std::string> arg_set;
	std::map<VarnodeData, std::string> reglist;
	sanal.trans.getAllRegisters(reglist);
	for(auto iter = args.cbegin(); iter != args.cend(); ++iter)
	{
		for(auto p = reglist.cbegin(); p != reglist.cend(); ++p)
		{
			if(p->second == *iter)
			{
				arg_set.insert(*iter);
				break;
			}
		}
	}

	std::unordered_map<uintb, const Pcodeop *> midvar_op;
	for(auto pco = pcode_slg.pcodes.begin(); pco != pcode_slg.pcodes.end(); ++pco)
	{

		if(pco->input0 && pco->input0->is_unique())
		{
			UniquePcodeOperand* tmp = new UniquePcodeOperand(pco->input0);
			delete pco->input0;
			pco->input0 = (PcodeOperand *)tmp;
			tmp->def = midvar_op[tmp->offset];
		}
		if(pco->input1 && pco->input1->is_unique())
		{
			UniquePcodeOperand* tmp = new UniquePcodeOperand(pco->input1);
			delete pco->input1;
			pco->input1 = (PcodeOperand *)tmp;
			tmp->def = midvar_op[tmp->offset];
		}

		if(pco->type != CPUI_STORE)
		{
			if(pco->output && pco->output->is_unique())
				midvar_op[pco->output->offset] = &(*pco);
		}
		else
		{
			if(pco->output && pco->output->is_unique())
			{
				UniquePcodeOperand* tmp = new UniquePcodeOperand(pco->output);
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
	if(anal_type_INT_XXX(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_NOT(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_XPUSH(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_POP(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_STORE(anal, anal_op, pcode_slg.pcodes, arg_set))
		return;
	if(anal_type_LOAD(anal, anal_op, pcode_slg.pcodes, arg_set))
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
		    space->getTrans()->getRegisterName(data.space, data.offset, data.size).c_str());
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
				throw LowlevelError("print_unique: Can't find required unique varnodes in stack.");

			ss << index + offset << ",PICK";
			return true;
		}
		else
			return false;
	};
	auto push_stack = [&esil_stack](PcodeOperand *arg = nullptr) { esil_stack.push_back(arg); };

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
				ss << ",CLEAR,TODO";
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
						ss << *iter->input0;

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
						ss << *iter->input0;

					if(iter->output->is_unique())
						push_stack(iter->output);
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
						ss << *iter->input1;
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
						ss << *iter->output;

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
					ss << "," << *iter->input0 << "," << sanal.pc_name << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_CBRANCH:
			{
				if(iter->input0 && iter->input1)
				{
					if(!print_if_unique(iter->input1))
						ss << *iter->input1;
					ss << ",?{";

					if(iter->input0->is_const())
						// throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
						// This means conditional jump in P-codes
						goto branch_in_pcodes;
					ss << "," << *iter->input0 << "," << sanal.pc_name << ",=,}";
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
						ss << *iter->input0;
					ss << "," << iter->input1->size * 8 << ",SWAP,<<";

					ss << ",";
					if(!print_if_unique(iter->input1, 1))
						ss << *iter->input1;
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
						ss << *iter->input0;
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
						ss << *iter->input1;
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0;
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
						ss << *iter->input1;
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0;
					ss << ",";
					switch(iter->type)
					{
						case CPUI_INT_MULT: ss << "*"; break;
						case CPUI_INT_DIV: ss << "/"; break;
						case CPUI_INT_REM: ss << "%"; break;
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

			case CPUI_INT_SREM:
			case CPUI_INT_SDIV:
			{
				auto make_mask = [&ss](int4 bytes) { ss << "," << bytes * 8 << ",1,<<,1,SWAP,-"; };
				auto make_input = [&ss, &print_if_unique](PcodeOperand *input, int offset) {
					ss << ",";
					if(!print_if_unique(input))
						ss << *input;
				};
				auto make_2comp = [&ss, &make_input, &make_mask](PcodeOperand *input,
				                                                 int offset = 0) {
					make_input(input, offset);
					ss << ",DUP," << input->size * 8 - 1 << ",SWAP,>>,1,&,?{";
					make_mask(input->size);
					ss << ",^,1,+,}";
				};

				if(iter->input0 && iter->input1 && iter->output)
				{
					make_2comp(iter->input1);
					make_2comp(iter->input0, 1);
					ss << ",";
					switch(iter->type)
					{
						case CPUI_INT_SREM: ss << "%"; break;
						case CPUI_INT_SDIV: ss << "/"; break;
					} // Now, one unsigned result is on stack

					make_input(iter->input1, 1);
					ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";
					make_input(iter->input0, 2);
					ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^,?{";
					make_mask(iter->output->size);
					ss << ",^,1,+,}";

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
						ss << *iter->input0;
					ss << ",";
					if(!print_if_unique(iter->input1, 1))
						ss << *iter->input1;
					ss << ",+," << iter->input0->size * 8 << ",1,<<,1,SWAP,-,&";

					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0;
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
						ss << *iter->input0;
					ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",DUP,";
					if(!print_if_unique(iter->input1, 2))
						ss << *iter->input1;
					ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^,1,^,SWAP";

					ss << ",";
					if(!print_if_unique(iter->input0, 2))
						ss << *iter->input0;
					ss << ",";
					if(!print_if_unique(iter->input1, 3))
						ss << *iter->input1;
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
						ss << *iter->input1;
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0;
					ss << ",-," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",DUP,";
					if(!print_if_unique(iter->input1, 2))
						ss << *iter->input1;
					ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^,1,^,SWAP";

					ss << ",";
					if(!print_if_unique(iter->input0, 2))
						ss << *iter->input0;
					ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^";

					ss << ",";
					if(!print_if_unique(iter->input1, 3))
						ss << *iter->input1;
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

			case CPUI_BOOL_NEGATE:
			case CPUI_INT_NEGATE:
			case CPUI_INT_2COMP:
			{
				if(iter->input0 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0;

					if(iter->type == CPUI_BOOL_NEGATE)
						ss << ",!";
					else
					{
						ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,^";
						ss << (iter->type == CPUI_INT_2COMP) ? ",1,+" : "";
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
						ss << *iter->input0;

					switch(iter->type)
					{
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
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_POPCOUNT:
			{
				if(iter->input0 && iter->output)
				{
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0;

					std::string stmp = ss.str();
					ss << ",0,SWAP,DUP,?{,SWAP,1,+,SWAP,DUP,1,SWAP,-,&,DUP,?{,";
					ss << 2 + std::count(stmp.begin(), stmp.end(), ',');
					ss << ",GOTO,},},+";

					if(iter->output->is_unique())
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				}
				else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}
		}
	}

	if(!esil_stack.empty())
		ss << ",CLEAR";
	esilprintf(anal_op, ss.str()[0] == ',' ? ss.str().c_str() + 1 : ss.str().c_str());
}

static int sleigh_op(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len,
                     RAnalOpMask mask)
{
	anal_op->jump = UT64_MAX;
	anal_op->fail = UT64_MAX;
	anal_op->ptr = anal_op->val = UT64_MAX;
	anal_op->addr = addr;
	anal_op->sign = true;
	anal_op->type = R_ANAL_OP_TYPE_ILL;
	anal_op->id = -1;

	PcodeSlg pcode_slg;
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

	if(mask & R_ANAL_OP_MASK_ESIL)
		sleigh_esil(a, anal_op, addr, data, len, pcode_slg.pcodes);

	SleighInstruction &ins = *sanal.trans.getInstruction(caddr);
	FlowType ftype = ins.getFlowType();
	bool isRefed = false;

	//std::cerr << caddr << " " << ins.printFlowType(ftype) << std::endl;
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
	else // Label each instruction based on a series of P-codes.
		anal_type(a, anal_op, pcode_slg, assem);

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
	const std::string &group = sanal.reg_group[name];

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

static char *get_reg_profile(RAnal *anal)
{
	if(!strcmp(anal->cpu, "x86"))
		return nullptr;

	sanal.init(anal);

	auto reg_list = sanal.getRegs();
	std::stringstream buf;

	for(auto p = reg_list.begin(); p != reg_list.end(); p++)
	{
		const std::string &group = sanal.reg_group[p->name];
		if(group.empty())
		{
			buf << "gpr\t" << p->name << "\t." << p->size * 8 << "\t" << p->offset << "\t"
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

		buf << p->name << "\t." << p->size * 8 << "\t" << p->offset << "\t"
		    << "0\n";
	}

	if(!sanal.pc_name.empty())
		buf << "=PC\t" << sanal.pc_name << '\n';
	if(!sanal.sp_name.empty())
		buf << "=SP\t" << sanal.sp_name << '\n';

	for(unsigned i = 0; i != sanal.arg_names.size() && i <= 9; ++i)
		buf << "=A" << i << '\t' << sanal.arg_names[i] << '\n';

	for(unsigned i = 0; i != sanal.ret_names.size() && i <= 3; ++i)
		buf << "=R" << i << '\t' << sanal.ret_names[i] << '\n';

	const std::string &res = buf.str();
	// fprintf(stderr, res.c_str());
	return strdup(res.c_str());
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
		throw LowlevelError("sleigh_esil_consts_pick: argument is consts only");
		goto end;
	}
	if(!idx || !r_anal_esil_get_parm(esil, idx, &i))
	{
		throw LowlevelError("esil_pick: invalid index number");
		goto end;
	}
	if(esil->stackptr < i)
	{
		throw LowlevelError("esil_pick: index out of stack bounds");
		goto end;
	}
	if(!esil->stack[esil->stackptr - i])
	{
		throw LowlevelError("esil_pick: undefined element");
		goto end;
	}
	if(!r_anal_esil_push(esil, esil->stack[esil->stackptr - i]))
	{
		throw LowlevelError("ESIL stack is full");
		esil->trap = 1;
		esil->trap_code = 1;
		goto end;
	}
	ret = true;
end:
	free(idx);
	return ret;
}

constexpr int ESIL_PARM_FLOAT = 127; // Avoid conflict

static bool esil_pushnum_float(RAnalEsil *esil, long double num)
{
	char str[64];
	snprintf(str, sizeof(str) - 1, "%.*LeF\n", DECIMAL_DIG, num);
	return r_anal_esil_push(esil, str);
}

static int esil_get_parm_type_float(RAnalEsil *esil, const char *str)
{
	int len, i;

	if(!str || !(len = strlen(str)))
		return R_ANAL_ESIL_PARM_INVALID;

	if((str[len - 1] == 'F') && (str[1] == '.' || (str[2] == '.' && str[0] == '-')))
		return ESIL_PARM_FLOAT;
	if(!strcmp(str, "nan") || !strcmp(str, "inf"))
		return ESIL_PARM_FLOAT;
	if(!((IS_DIGIT(str[0])) || str[0] == '-'))
		goto not_a_number;

	return ESIL_PARM_FLOAT;
not_a_number:
	if(r_reg_get(esil->anal->reg, str, get_reg_type(str)))
		return R_ANAL_ESIL_PARM_REG;

	return R_ANAL_ESIL_PARM_INVALID;
}

static int esil_get_parm_float(RAnalEsil *esil, const char *str, long double *num)
{
	if(!str || !*str)
		return false;

	int parm_type = esil_get_parm_type_float(esil, str);
	if(!num || !esil)
		return false;

	switch(parm_type)
	{
		case ESIL_PARM_FLOAT:
			// *num = r_num_get (NULL, str);
			scanf("%LfF", num);
			return true;
		case R_ANAL_ESIL_PARM_REG:
			if(!r_anal_esil_reg_read(esil, str, (ut64 *)num, nullptr))
			{
				break;
			}
			return true;
		default:
			if(esil->verbose)
			{
				eprintf("Invalid arg (%s)\n", str);
			}
			esil->parse_stop = 1;
			break;
	}
	return false;
}

static bool sleigh_esil_is_nan(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src && esil_get_parm_float(esil, src, &s))
		ret = r_anal_esil_pushnum(esil, isnan(s));
	else
		throw LowlevelError("sleigh_esil_is_nan: invalid parameters");

	free(src);
	return ret;
}

static bool sleigh_esil_int_to_float(RAnalEsil *esil)
{
	bool ret = false;
	st64 s;
	char *src = r_anal_esil_pop(esil);
	if(src && r_anal_esil_get_parm(esil, src, (ut64 *)&s))
		ret = esil_pushnum_float(esil, (long double)s * 1.0);
	else
		throw LowlevelError("sleigh_esil_int_to_float: invalid parameters");

	free(src);
	return ret;
}

static bool sleigh_esil_float_to_int(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src && esil_get_parm_float(esil, src, &s))
	{
		if(isnan(s) || isinf(s))
			throw LowlevelError("sleigh_esil_float_to_int: nan or inf detected.");
		ret = r_anal_esil_pushnum(esil, (st64)(s));
	}
	else
		throw LowlevelError("sleigh_esil_float_to_int: invalid parameters");

	free(src);
	return ret;
}

static bool sleigh_esil_float_to_float(RAnalEsil *esil)
{
	bool ret = false;
	long double d;
	ut64 s = 0;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && r_anal_esil_get_parm(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(d) || isinf(d))
			ret = r_anal_esil_pushnum(esil, d);
		else if(s == 4)
			ret = r_anal_esil_pushnum(esil, (float)d);
		else if(s == 8)
			ret = r_anal_esil_pushnum(esil, (double)d);
		else
			throw LowlevelError(
			    "sleigh_esil_float_to_float: byte-width of float number overflows.");
	}
	else
		throw LowlevelError("sleigh_esil_float_to_float: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_cmp(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, s == d);
	}
	else
		throw LowlevelError("sleigh_esil_float_cmp: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_negcmp(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, s != d);
	}
	else
		throw LowlevelError("sleigh_esil_float_negcmp: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_less(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, s < d);
	}
	else
		throw LowlevelError("sleigh_esil_float_less: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_lesseq(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(s) || isnan(d))
			ret = r_anal_esil_pushnum(esil, 0);
		else
			ret = r_anal_esil_pushnum(esil, s <= d);
	}
	else
		throw LowlevelError("sleigh_esil_float_lesseq: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_add(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
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
		throw LowlevelError("sleigh_esil_float_add: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_sub(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, s);
		else if(isnan(d))
			ret = esil_pushnum_float(esil, d);
		else
		{
			feclearexcept(FE_OVERFLOW);
			long double tmp = s - d;
			auto raised = fetestexcept(FE_OVERFLOW);
			if(raised & FE_OVERFLOW)
				ret = esil_pushnum_float(esil, 0.0 / 0.0);
			else
				ret = esil_pushnum_float(esil, s + d);
		}
	}
	else
		throw LowlevelError("sleigh_esil_float_sub: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_mul(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, s);
		else if(isnan(d))
			ret = esil_pushnum_float(esil, d);
		else
		{
			feclearexcept(FE_OVERFLOW);
			long double tmp = s - d;
			auto raised = fetestexcept(FE_OVERFLOW);
			if(raised & FE_OVERFLOW)
				ret = esil_pushnum_float(esil, 0.0 / 0.0);
			else
				ret = esil_pushnum_float(esil, s * d);
		}
	}
	else
		throw LowlevelError("sleigh_esil_float_mul: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_div(RAnalEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);
	if((src && esil_get_parm_float(esil, src, &s)) && (dst && esil_get_parm_float(esil, dst, &d)))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, s);
		else if(isnan(d))
			ret = esil_pushnum_float(esil, d);
		else
		{
			feclearexcept(FE_OVERFLOW);
			long double tmp = s - d;
			auto raised = fetestexcept(FE_OVERFLOW);
			if(raised & FE_OVERFLOW)
				ret = esil_pushnum_float(esil, 0.0 / 0.0);
			else
				ret = esil_pushnum_float(esil, s / d);
		}
	}
	else
		throw LowlevelError("sleigh_esil_float_div: invalid parameters");

	free(src);
	free(dst);
	return ret;
}

static bool sleigh_esil_float_neg(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src && esil_get_parm_float(esil, src, &s))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, 0.0 / 0.0);
		else
			ret = esil_pushnum_float(esil, -s);
	}
	else
		throw LowlevelError("sleigh_esil_float_neg: invalid parameters");

	free(src);
	return ret;
}

static bool sleigh_esil_float_ceil(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src && esil_get_parm_float(esil, src, &s))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, 0.0 / 0.0);
		else
			ret = esil_pushnum_float(esil, std::ceil(s));
	}
	else
		throw LowlevelError("sleigh_esil_float_ceil: invalid parameters");

	free(src);
	return ret;
}

static bool sleigh_esil_float_floor(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src && esil_get_parm_float(esil, src, &s))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, 0.0 / 0.0);
		else
			ret = esil_pushnum_float(esil, std::floor(s));
	}
	else
		throw LowlevelError("sleigh_esil_float_floor: invalid parameters");

	free(src);
	return ret;
}

static bool sleigh_esil_float_round(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src && esil_get_parm_float(esil, src, &s))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, 0.0 / 0.0);
		else
			ret = esil_pushnum_float(esil, std::round(s));
	}
	else
		throw LowlevelError("sleigh_esil_float_round: invalid parameters");

	free(src);
	return ret;
}

static bool sleigh_esil_float_sqrt(RAnalEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = r_anal_esil_pop(esil);
	if(src && esil_get_parm_float(esil, src, &s))
	{
		if(isnan(s))
			ret = esil_pushnum_float(esil, 0.0 / 0.0);
		else
			ret = esil_pushnum_float(esil, std::sqrt(s));
	}
	else
		throw LowlevelError("sleigh_esil_float_sqrt: invalid parameters");

	free(src);
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
		throw LowlevelError("sleigh_esil_signext: invalid parameters");
		free(p_src);
		return false;
	}
	else
		free(p_src);

	char *p_dst = r_anal_esil_pop(esil);
	if(!p_dst)
		return false;

	if(!r_anal_esil_get_parm(esil, p_dst, &dst))
	{
		throw LowlevelError("sleigh_esil_signext: invalid parameters");
		free(p_dst);
		return false;
	}
	else
		free(p_dst);

	ut64 m = 0;
	if(dst < 64)
		m = 1ULL << (dst - 1);

	// dst = (dst & ((1U << src_bit) - 1)); // clear upper bits
	return r_anal_esil_pushnum(esil, ((src ^ m) - m));
}

static int esil_sleigh_init(RAnalEsil *esil)
{
	if(!esil)
		return false;

	// Only consts-only version PICK will meet my demand
	r_anal_esil_set_op(esil, "PICK", sleigh_esil_consts_pick, 1, 0, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "NAN", sleigh_esil_is_nan, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "I2F", sleigh_esil_int_to_float, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F2I", sleigh_esil_float_to_int, 1, 1, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F2F", sleigh_esil_float_to_float, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_op(esil, "F==", sleigh_esil_float_cmp, 1, 2, R_ANAL_ESIL_OP_TYPE_CUSTOM);
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

	return true;
}

static int esil_sleigh_fini(RAnalEsil *esil)
{
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
