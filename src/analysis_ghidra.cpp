// SPDX-FileCopyrightText: 2020-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-FileCopyrightText: 2020 pancake <pancake@youterm.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <rz_lib.h>
#include <rz_analysis.h>
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cfenv>
#include <limits>
#include "SleighAsm.h"
#include "SleighAnalysisValue.h"

using namespace ghidra;

static SleighAsm sanalysis;

static int archinfo(RzAnalysis *analysis, RzAnalysisInfoType query)
{
	// This is to check if RzCore plugin set cpu properly.
	if(!analysis->cpu)
		return -1;

	ut64 length = strlen(analysis->cpu), i = 0;
	for(; i < length && analysis->cpu[i] != ':'; ++i) {}
	if(i == length)
		return -1;

	try
	{
		sanalysis.init(analysis->cpu, analysis->bits, analysis->big_endian, SleighAsm::getConfig(analysis));
	}
	catch(const LowlevelError &e)
	{
		std::cerr << "SleighInit " << e.explain << std::endl;
		return -1;
	}

	if(query == RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN)
		return sanalysis.alignment;
	else
		return -1;
}

static std::vector<std::string> string_split(const std::string &s)
{
	std::vector<std::string> tokens;
	for(ut64 i = 0; i < s.size();)
	{
		std::string tmp;
		while(i < s.size() && !std::isalnum(s[i]))
			++i;
		while(i < s.size() && std::isalnum(s[i]))
			tmp.push_back(s[i++]);
		tokens.emplace_back(tmp);
	}
	return tokens;
}

static inline bool reg_set_has(const std::unordered_set<std::string> &reg_set,
                               const SleighAnalysisValue &value)
{
	if(!value.is_reg())
		return false;

	if(value.reg && reg_set.find(value.reg->name) != reg_set.end())
		return true;
	if(value.regdelta && reg_set.find(value.regdelta->name) != reg_set.end())
		return true;
	return false;
}

/* After some consideration, I decide to classify mov operation:
 * RZ_ANALYSIS_OP_TYPE_STORE:
 *     CONST -> MEM (Key: STORE)
 *     CONST -> MEM (Key: COPY)
 *     REG -> MEM (Key: STORE)
 *     REG -> MEM (Key: COPY)
 * RZ_ANALYSIS_OP_TYPE_LOAD:
 *     MEM -> REG (Key: LOAD)
 *     MEM -> REG (Key: COPY)
 * RZ_ANALYSIS_OP_TYPE_MOV:
 *     REG   -> REG (Key: COPY)
 *     CONST -> REG (Key: COPY)
 *     CONST -> MEM (Key: STORE)
 *     MEM   -> MEM (Key: LOAD & STORE) // Never happen as far as I know
 */

static ut32 analysis_type_MOV(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &reg_set)
{
	const ut32 this_type = RZ_ANALYSIS_OP_TYPE_MOV;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	const PcodeOpType key_pcode_store = CPUI_STORE;
	SleighAnalysisValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalysisValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_copy)
		{
			if(iter->output)
				outs = SleighAnalysisValue::resolve_out(analysis, iter, raw_ops.cend(), iter->output);

			auto p = outs.cbegin();
			for(; p != outs.cend() && !reg_set_has(reg_set, *p); ++p) {}
			if(p != outs.cend())
			{
				out = *p;

				if(iter->input0)
					in0 = SleighAnalysisValue::resolve_arg(analysis, iter->input0);

				if(in0.is_valid() && (in0.is_imm() || reg_set_has(reg_set, in0)))
				{
					analysis_op->type = this_type;
					analysis_op->src[0] = in0.dup();
					analysis_op->dst = out.dup();

					return this_type;
				}
			}
		}

		if(iter->type == key_pcode_store)
		{
			if(iter->output)
				in0 = SleighAnalysisValue::resolve_arg(analysis, iter->output);

			if(iter->input1)
				out = SleighAnalysisValue::resolve_arg(analysis, iter->input1);

			if(in0.is_valid() && out.is_valid() && in0.is_imm())
			{
				out.mem(iter->output->size);

				analysis_op->type = this_type;
				analysis_op->src[0] = in0.dup();
				analysis_op->dst = out.dup();

				return this_type;
			}
		}
	}

	return 0;
}

static ut32 analysis_type_LOAD(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &reg_set)
{
	/*
	 * RZ_ANALYSIS_OP_TYPE_LOAD:
	 *     MEM -> REG (Key: LOAD)
	 *     MEM -> REG (Key: COPY)
	 */
	const ut32 this_type = RZ_ANALYSIS_OP_TYPE_LOAD;
	const PcodeOpType key_pcode_load = CPUI_LOAD;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	SleighAnalysisValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalysisValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_load || iter->type == key_pcode_copy)
		{
			if(iter->output)
				outs = SleighAnalysisValue::resolve_out(analysis, iter, raw_ops.cend(), iter->output);

			auto p = outs.cbegin();
			for(; p != outs.cend() && !reg_set_has(reg_set, *p); ++p) {}
			if(p != outs.cend())
			{
				out = *p;

				if(iter->type == key_pcode_load? iter->input1: iter->input0)
				{
					in0 = SleighAnalysisValue::resolve_arg(analysis,
					                  iter->type == key_pcode_load? iter->input1: iter->input0);

					if(iter->type == key_pcode_load && in0.is_valid())
						in0.mem(iter->output->size);
				}

				if(in0.is_valid() && in0.is_mem())
				{
					analysis_op->type = this_type;
					analysis_op->src[0] = in0.dup();
					analysis_op->dst = out.dup();

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 analysis_type_STORE(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                            const std::unordered_set<std::string> &reg_set)
{
	/*
	 * RZ_ANALYSIS_OP_TYPE_STORE:
	 *     CONST -> MEM (Key: STORE)
	 *     CONST -> MEM (Key: COPY)
	 *     REG -> MEM (Key: STORE)
	 *     REG -> MEM (Key: COPY)
	 */
	const ut32 this_type = RZ_ANALYSIS_OP_TYPE_STORE;
	const PcodeOpType key_pcode_store = CPUI_STORE;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	SleighAnalysisValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalysisValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_store)
		{
			if(iter->output && iter->input1)
				in0 = SleighAnalysisValue::resolve_arg(analysis, iter->output);

			if(!in0.is_valid() || !(in0.is_imm() || reg_set_has(reg_set, in0)))
				continue;

			out = SleighAnalysisValue::resolve_arg(analysis, iter->input1);

			if(out.is_valid())
			{
				out.mem(iter->output->size);

				analysis_op->type = this_type;
				analysis_op->src[0] = in0.dup();
				analysis_op->dst = out.dup();

				return this_type;
			}
		}

		if(iter->type == key_pcode_copy)
		{
			if(iter->input0 && iter->output)
				in0 = SleighAnalysisValue::resolve_arg(analysis, iter->input0);

			if(!in0.is_valid() || !(in0.is_imm() || reg_set_has(reg_set, in0)))
				continue;

			outs = SleighAnalysisValue::resolve_out(analysis, iter, raw_ops.cend(), iter->output);

			auto p = outs.cbegin();
			for(; p != outs.cend(); ++p)
			{
				out = *p;

				if(out.is_valid() && out.is_mem())
				{
					analysis_op->type = this_type;
					analysis_op->src[0] = in0.dup();
					analysis_op->dst = out.dup();

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 analysis_type_XSWI(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &reg_set)
{
	// RZ_ANALYSIS_OP_TYPE_CSWI
	// RZ_ANALYSIS_OP_TYPE_SWI
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
				analysis_op->val = iter->input1->number;

			analysis_op->type = has_cbranch? RZ_ANALYSIS_OP_TYPE_CSWI: RZ_ANALYSIS_OP_TYPE_SWI;

			return analysis_op->type;
		}
	}

	return 0;
}

static ut32 analysis_type_XPUSH(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                            const std::unordered_set<std::string> &reg_set)
{
	// RZ_ANALYSIS_OP_TYPE_UPUSH
	// RZ_ANALYSIS_OP_TYPE_RPUSH
	// RZ_ANALYSIS_OP_TYPE_PUSH
	const PcodeOpType key_pcode = CPUI_STORE;
	SleighAnalysisValue out, in;
	out.invalid(); in.invalid();

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode)
		{
			if(iter->input1)
				out = SleighAnalysisValue::resolve_arg(analysis, iter->input1);

			if(!out.is_valid())
				continue;

			out.mem(iter->output->size);

			if((out.reg && sanalysis.reg_mapping[sanalysis.sp_name] == out.reg->name) ||
			   (out.regdelta && sanalysis.reg_mapping[sanalysis.sp_name] == out.regdelta->name))
			{
				analysis_op->type = RZ_ANALYSIS_OP_TYPE_UPUSH;
				analysis_op->stackop = RZ_ANALYSIS_STACK_INC;

				if(iter->output)
					in = SleighAnalysisValue::resolve_arg(analysis, iter->output);

				if(!in.is_valid())
					continue;

				if(reg_set_has(reg_set, in))
					analysis_op->type = RZ_ANALYSIS_OP_TYPE_RPUSH;
				analysis_op->src[0] = in.dup();
				analysis_op->dst = out.dup();

				return analysis_op->type;
			}
		}
	}

	return 0;
}

static ut32 analysis_type_POP(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &reg_set)
{
	const ut32 this_type = RZ_ANALYSIS_OP_TYPE_POP;
	const PcodeOpType key_pcode = CPUI_LOAD;
	SleighAnalysisValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalysisValue> outs;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode)
		{
			if(iter->input1)
				in0 = SleighAnalysisValue::resolve_arg(analysis, iter->input1);

			if(!in0.is_valid())
				continue;

			if((in0.reg && sanalysis.reg_mapping[sanalysis.sp_name] == in0.reg->name) ||
			   (in0.regdelta && sanalysis.reg_mapping[sanalysis.sp_name] == in0.regdelta->name))
			{
				if(iter->output)
					outs = SleighAnalysisValue::resolve_out(analysis, iter, raw_ops.cend(), iter->output);

				auto p = outs.cbegin();
				for(; p != outs.cend() && !reg_set_has(reg_set, *p); ++p) {}
				if(p == outs.cend())
					continue;
				out = *p;

				analysis_op->type = this_type;
				analysis_op->stackop = RZ_ANALYSIS_STACK_INC;
				analysis_op->dst = out.dup();
				analysis_op->src[0] = in0.dup();

				return this_type;
			}
		}
	}

	return 0;
}

static ut32 analysis_type_XCMP(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &reg_set)
{
	// RZ_ANALYSIS_OP_TYPE_CMP
	// RZ_ANALYSIS_OP_TYPE_ACMP
	const PcodeOpType key_pcode_sub = CPUI_INT_SUB;
	const PcodeOpType key_pcode_and = CPUI_INT_AND;
	const PcodeOpType key_pcode_equal = CPUI_INT_EQUAL;
	SleighAnalysisValue in0, in1;
	in0.invalid(); in1.invalid();
	uintb unique_off = 0;
	PcodeOpType key_pcode = CPUI_MAX;

	analysis_op->type = RZ_ANALYSIS_OP_TYPE_CMP;
	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_sub || iter->type == key_pcode_and)
		{
			if(iter->input0)
				in0 = SleighAnalysisValue::resolve_arg(analysis, iter->input0);

			if(iter->input1)
				in1 = SleighAnalysisValue::resolve_arg(analysis, iter->input1);

			if((in0.is_valid() && reg_set_has(reg_set, in0)) || (in1.is_valid() && reg_set_has(reg_set, in1)))
			{
				if(iter->output && iter->output->is_unique())
				{
					unique_off = iter->output->offset;
					key_pcode = iter->type;
				}
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

			analysis_op->type = key_pcode == key_pcode_sub? RZ_ANALYSIS_OP_TYPE_CMP: RZ_ANALYSIS_OP_TYPE_ACMP;
			// analysis_op->cond = RZ_ANALYSIS_COND_EQ; Should I enable this? I think sub can judge equal and
			// less or more.
			analysis_op->src[0] = in0.dup();
			analysis_op->src[1] = in1.dup();

			return analysis_op->type;
		}
	}

	return 0;
}

static ut32 analysis_type_XXX(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                              const std::unordered_set<std::string> &reg_set)
{
	// RZ_ANALYSIS_OP_TYPE_ADD
	// RZ_ANALYSIS_OP_TYPE_SUB
	// RZ_ANALYSIS_OP_TYPE_MUL
	// RZ_ANALYSIS_OP_TYPE_DIV
	// RZ_ANALYSIS_OP_TYPE_MOD
	// RZ_ANALYSIS_OP_TYPE_OR
	// RZ_ANALYSIS_OP_TYPE_AND
	// RZ_ANALYSIS_OP_TYPE_XOR
	// RZ_ANALYSIS_OP_TYPE_SHR
	// RZ_ANALYSIS_OP_TYPE_SHL
	// RZ_ANALYSIS_OP_TYPE_SAR
	SleighAnalysisValue in0, in1, out;
	in0.invalid(); in1.invalid(); out.invalid();
	std::vector<SleighAnalysisValue> outs;

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
					in0 = SleighAnalysisValue::resolve_arg(analysis, iter->input0);
					in1 = SleighAnalysisValue::resolve_arg(analysis, iter->input1);
				}

				if((in0.is_valid() && reg_set_has(reg_set, in0)) || (in1.is_valid() && reg_set_has(reg_set, in1)))
				{
					if(iter->output)
						outs = SleighAnalysisValue::resolve_out(analysis, iter, raw_ops.cend(), iter->output);

					auto p = outs.cbegin();
					for(; p != outs.cend() && !reg_set_has(reg_set, *p); ++p) {}
					if(p != outs.cend())
					{
						out = *p;

						switch(iter->type)
						{
							case CPUI_INT_ADD: analysis_op->type = RZ_ANALYSIS_OP_TYPE_ADD; break;
							case CPUI_INT_SUB: analysis_op->type = RZ_ANALYSIS_OP_TYPE_SUB; break;
							case CPUI_INT_MULT: analysis_op->type = RZ_ANALYSIS_OP_TYPE_MUL; break;
							case CPUI_INT_DIV: analysis_op->type = RZ_ANALYSIS_OP_TYPE_DIV; break;
							case CPUI_INT_REM:
							case CPUI_INT_SREM: analysis_op->type = RZ_ANALYSIS_OP_TYPE_MOD; break;
							case CPUI_INT_OR: analysis_op->type = RZ_ANALYSIS_OP_TYPE_OR; break;
							case CPUI_INT_AND: analysis_op->type = RZ_ANALYSIS_OP_TYPE_AND; break;
							case CPUI_INT_XOR: analysis_op->type = RZ_ANALYSIS_OP_TYPE_XOR; break;
							case CPUI_INT_RIGHT: analysis_op->type = RZ_ANALYSIS_OP_TYPE_SHR; break;
							case CPUI_INT_LEFT: analysis_op->type = RZ_ANALYSIS_OP_TYPE_SHL; break;
							case CPUI_INT_SRIGHT: analysis_op->type = RZ_ANALYSIS_OP_TYPE_SAR; break;
							default: break;
						}
						analysis_op->src[0] = in0.dup();
						analysis_op->src[1] = in1.dup();
						analysis_op->dst = out.dup();

						return analysis_op->type;
					}
				}
			}
			break;

			default: break;
		}
	}

	return 0;
}

static ut32 analysis_type_NOR(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &reg_set)
{
	const ut32 this_type = RZ_ANALYSIS_OP_TYPE_NOR;
	const PcodeOpType key_pcode_or = CPUI_INT_OR;
	const PcodeOpType key_pcode_negate = CPUI_INT_NEGATE;
	SleighAnalysisValue in0, in1, out;
	in0.invalid(); in1.invalid(); out.invalid();
	std::vector<SleighAnalysisValue> outs;
	uintb unique_off = 0;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode_or)
		{
			if(iter->input0 && iter->input1)
			{
				in0 = SleighAnalysisValue::resolve_arg(analysis, iter->input0);
				in1 = SleighAnalysisValue::resolve_arg(analysis, iter->input1);
			}

			if((in0.is_valid() && reg_set_has(reg_set, in0)) || (in1.is_valid() && reg_set_has(reg_set, in1)))
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
					outs = SleighAnalysisValue::resolve_out(analysis, iter, raw_ops.cend(), iter->output);

				auto p = outs.cbegin();
				for(; p != outs.cend() && !reg_set_has(reg_set, *p); ++p) {}
				if(p != outs.cend())
				{
					out = *p;

					analysis_op->type = this_type;
					analysis_op->src[0] = in0.dup();
					analysis_op->src[1] = in1.dup();
					analysis_op->dst = out.dup();

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 analysis_type_NOT(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &reg_set)
{
	const ut32 this_type = RZ_ANALYSIS_OP_TYPE_NOT;
	const PcodeOpType key_pcode = CPUI_INT_NEGATE;
	SleighAnalysisValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalysisValue> outs;
	uintb unique_off = 0;

	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		if(iter->type == key_pcode)
		{
			if(iter->input0)
				in0 = SleighAnalysisValue::resolve_arg(analysis, iter->input0);

			if(in0.is_valid() && reg_set_has(reg_set, in0))
			{
				if(iter->output)
					outs = SleighAnalysisValue::resolve_out(analysis, iter, raw_ops.cend(), iter->output);

				auto p = outs.cbegin();
				for(; p != outs.cend() && !reg_set_has(reg_set, *p); ++p) {}
				if(p != outs.cend())
				{
					out = *p;

					analysis_op->type = this_type;
					analysis_op->src[0] = in0.dup();
					analysis_op->dst = out.dup();

					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 analysis_type_XCHG(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &reg_set)
{
	const ut32 this_type = RZ_ANALYSIS_OP_TYPE_XCHG;
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

		analysis_op->type = this_type;
		analysis_op->src[0] = SleighAnalysisValue::resolve_arg(analysis, copy_vec[0]->input0).dup();
		analysis_op->dst = SleighAnalysisValue::resolve_arg(analysis, copy_vec[2]->output).dup();

		return this_type;
	}

fail:
	return 0;
}

static ut32 analysis_type_SINGLE(RzAnalysis *analysis, RzAnalysisOp *analysis_op, const std::vector<Pcodeop> &raw_ops,
                             const std::unordered_set<std::string> &reg_set)
{
	// RZ_ANALYSIS_OP_TYPE_CAST
	// RZ_ANALYSIS_OP_TYPE_NEW
	// RZ_ANALYSIS_OP_TYPE_ABS
	for(auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); ++iter)
	{
		switch(iter->type)
		{
			case CPUI_CAST: analysis_op->type = RZ_ANALYSIS_OP_TYPE_CAST; return analysis_op->type;
			case CPUI_NEW: analysis_op->type = RZ_ANALYSIS_OP_TYPE_NEW; return analysis_op->type;
			case CPUI_FLOAT_ABS: analysis_op->type = RZ_ANALYSIS_OP_TYPE_ABS; return analysis_op->type;
			default: break;
		}
	}

	return 0;
}

static void analysis_type(RzAnalysis *analysis, RzAnalysisOp *analysis_op, PcodeSlg &pcode_slg, AssemblySlg &assem)
{
	std::vector<std::string> args = string_split(assem.str);
	std::unordered_set<std::string> reg_set;
	std::map<VarnodeData, std::string> reglist;
	sanalysis.trans.getAllRegisters(reglist);
	for(auto iter = args.cbegin(); iter != args.cend(); ++iter)
	{
		for(auto p = reglist.cbegin(); p != reglist.cend(); ++p)
		{
			if(sanalysis.reg_mapping[p->second] == *iter)
			{
				reg_set.insert(*iter);
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

	analysis_op->type = RZ_ANALYSIS_OP_TYPE_UNK;

	if(analysis_type_XCHG(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_SINGLE(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_XSWI(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_XCMP(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_NOR(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_XPUSH(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_POP(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_STORE(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_LOAD(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_XXX(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_NOT(analysis, analysis_op, pcode_slg.pcodes, reg_set))
		return;
	if(analysis_type_MOV(analysis, analysis_op, pcode_slg.pcodes, reg_set))
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
		    sanalysis
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

static void sleigh_esil(RzAnalysis *a, RzAnalysisOp *analysis_op, ut64 addr, const ut8 *data, int len,
                        const std::vector<Pcodeop> &Pcodes)
{
	std::vector<PcodeOperand *> esil_stack;
	std::stringstream ss;

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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");

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
							ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
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
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
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
						ss << *iter->output << (iter->output->is_reg()? ",NUM": "");

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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
					ss << "," << sanalysis.reg_mapping[sanalysis.pc_name] << ",=";
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
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
					ss << ",?{";

					if(iter->input0->is_const())
						// throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
						// This means conditional jump in P-codes
						goto branch_in_pcodes;
					ss << ",";
					if(!print_if_unique(iter->input0))
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
					ss << "," << sanalysis.reg_mapping[sanalysis.pc_name] << ",=,}";
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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
					ss << "," << iter->input1->size * 8 << ",SWAP,<<";

					ss << ",";
					if(!print_if_unique(iter->input1, 1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
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
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
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
						default: break;
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
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
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
						default: break;
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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
					ss << ",";
					if(!print_if_unique(iter->input1, 1))
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
					ss << ",+," << iter->input0->size * 8 << ",1,<<,1,SWAP,-,&";

					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
					ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",DUP,";
					if(!print_if_unique(iter->input1, 2))
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
					ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^,1,^,SWAP";

					ss << ",";
					if(!print_if_unique(iter->input0, 2))
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
					ss << ",";
					if(!print_if_unique(iter->input1, 3))
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
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
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
					ss << ",";
					if(!print_if_unique(iter->input0, 1))
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
					ss << ",-," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",DUP,";
					if(!print_if_unique(iter->input1, 2))
						ss << *iter->input1 << (iter->input1->is_reg()? ",NUM": "");
					ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

					ss << ",^,1,^,SWAP";

					ss << ",";
					if(!print_if_unique(iter->input0, 2))
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");
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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");

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
						ss << *iter->input0 << (iter->input0->is_reg()? ",NUM": "");

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
						default: break;
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
						default: break;
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
			default:
				break;
		}
	}

	if(!esil_stack.empty())
		ss << ",CLEAR";
	// std::cerr << hex << analysis_op->addr << " " << ss.str() << endl;
	esilprintf(analysis_op, "%s", ss.str()[0] == ','? ss.str().c_str() + 1: ss.str().c_str());
}

/* Not in use for now.
static bool analysis_type_NOP(const std::vector<Pcodeop> &Pcodes)
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
*/

static int sleigh_op(RzAnalysis *a, RzAnalysisOp *analysis_op, ut64 addr, const ut8 *data, int len,
                     RzAnalysisOpMask mask)
{
	try
	{
		sanalysis.init(a->cpu, a->bits, a->big_endian, SleighAsm::getConfig(a));

		analysis_op->addr = addr;
		analysis_op->sign = true;
		analysis_op->type = RZ_ANALYSIS_OP_TYPE_ILL;

		PcodeSlg pcode_slg(&sanalysis);
		AssemblySlg assem(&sanalysis);
		Address caddr(sanalysis.trans.getDefaultCodeSpace(), addr);
		analysis_op->size = sanalysis.genOpcode(pcode_slg, caddr, data, len);
		if((analysis_op->size < 1) || (sanalysis.trans.printAssembly(assem, caddr) < 1))
			return analysis_op->size; // When current place has no available code, return ILL.

		if(pcode_slg.pcodes.empty())
		{ // NOP case
			analysis_op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			esilprintf(analysis_op, "");
			return analysis_op->size;
		}

		std::unique_ptr<SleighInstruction> sinsn(sanalysis.trans.getInstruction(caddr));
		SleighInstruction &ins = *sinsn;
		FlowType ftype = ins.getFlowType();
		bool isRefed = false;

		// std::cerr << caddr << " " << ins.printFlowType(ftype) << std::endl;
		if(ftype != FlowType::FALL_THROUGH)
		{
			switch(ftype)
			{
				case FlowType::TERMINATOR:
					// Stack info could be added
					analysis_op->type = RZ_ANALYSIS_OP_TYPE_RET;
					analysis_op->eob = true;
					break;

				case FlowType::CONDITIONAL_TERMINATOR:
					analysis_op->type = RZ_ANALYSIS_OP_TYPE_CRET;
					analysis_op->fail = ins.getFallThrough().getOffset();
					analysis_op->eob = true;
					break;

				case FlowType::JUMP_TERMINATOR: analysis_op->eob = true;
				case FlowType::UNCONDITIONAL_JUMP:
					analysis_op->type = RZ_ANALYSIS_OP_TYPE_JMP;
					analysis_op->jump = ins.getFlows().begin()->getOffset();
					break;

				case FlowType::COMPUTED_JUMP:
				{
					char *reg = getIndirectReg(ins, isRefed);
					if(reg)
					{
						if(isRefed)
						{
							analysis_op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
							analysis_op->ireg = reg;
						}
						else
						{
							analysis_op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
							analysis_op->reg = reg;
						}
					}
					else
						analysis_op->type = RZ_ANALYSIS_OP_TYPE_IJMP;
					break;
				}

				case FlowType::CONDITIONAL_COMPUTED_JUMP:
				{
					char *reg = getIndirectReg(ins, isRefed);
					if(reg)
					{
						if(isRefed)
						{
							analysis_op->type = RZ_ANALYSIS_OP_TYPE_MCJMP;
							analysis_op->ireg = reg;
						}
						else
						{
							analysis_op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
							analysis_op->reg = reg;
						}
					}
					else
						analysis_op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
					analysis_op->fail = ins.getFallThrough().getOffset();
					break;
				}

				case FlowType::CONDITIONAL_JUMP:
					analysis_op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
					analysis_op->jump = ins.getFlows().begin()->getOffset();
					analysis_op->fail = ins.getFallThrough().getOffset();
					break;

				case FlowType::CALL_TERMINATOR: analysis_op->eob = true;
				case FlowType::UNCONDITIONAL_CALL:
					analysis_op->type = RZ_ANALYSIS_OP_TYPE_CALL;
					analysis_op->jump = ins.getFlows().begin()->getOffset();
					analysis_op->fail = ins.getFallThrough().getOffset();
					break;

				case FlowType::CONDITIONAL_COMPUTED_CALL:
				{
					char *reg = getIndirectReg(ins, isRefed);
					if(reg)
					{
						if(isRefed)
							analysis_op->ireg = reg;
						else
							analysis_op->reg = reg;
					}

					analysis_op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
					analysis_op->fail = ins.getFallThrough().getOffset();
					break;
				}

				case FlowType::CONDITIONAL_CALL:
					analysis_op->type |= RZ_ANALYSIS_OP_TYPE_CCALL;
					analysis_op->jump = ins.getFlows().begin()->getOffset();
					analysis_op->fail = ins.getFallThrough().getOffset();
					break;

				case FlowType::COMPUTED_CALL_TERMINATOR: analysis_op->eob = true;
				case FlowType::COMPUTED_CALL:
				{
					char *reg = getIndirectReg(ins, isRefed);
					if(reg)
					{
						if(isRefed)
						{
							analysis_op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
							analysis_op->ireg = reg;
						}
						else
						{
							analysis_op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
							analysis_op->reg = reg;
						}
					}
					else
						analysis_op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
					analysis_op->fail = ins.getFallThrough().getOffset();
					break;
				}

				default: throw LowlevelError("Unexpected FlowType occured in sleigh_op.");
			}
		}
		else
		{
			analysis_type(a, analysis_op, pcode_slg, assem);
#if 0
			switch(analysis_op->type)
			{
				case RZ_ANALYSIS_OP_TYPE_IRCALL: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_IRCALL"; break;
				case RZ_ANALYSIS_OP_TYPE_RET: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_RET"; break;
				case RZ_ANALYSIS_OP_TYPE_ABS: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_ABS"; break;
				case RZ_ANALYSIS_OP_TYPE_CRET: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_CRET"; break;
				case RZ_ANALYSIS_OP_TYPE_IJMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_IJMP"; break;
				case RZ_ANALYSIS_OP_TYPE_RPUSH: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_RPUSH"; break;
				case RZ_ANALYSIS_OP_TYPE_NOP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_NOP"; break;
				case RZ_ANALYSIS_OP_TYPE_SAR: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_SAR"; break;
				case RZ_ANALYSIS_OP_TYPE_NOT: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_NOT"; break;
				case RZ_ANALYSIS_OP_TYPE_CALL: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_CALL"; break;
				case RZ_ANALYSIS_OP_TYPE_UPUSH: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_UPUSH"; break;
				case RZ_ANALYSIS_OP_TYPE_LOAD: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_LOAD"; break;
				case RZ_ANALYSIS_OP_TYPE_XCHG: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_XCHG"; break;
				case RZ_ANALYSIS_OP_TYPE_RCJMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_RCJMP"; break;
				case RZ_ANALYSIS_OP_TYPE_CAST: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_CAST"; break;
				case RZ_ANALYSIS_OP_TYPE_UCJMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_UCJMP"; break;
				case RZ_ANALYSIS_OP_TYPE_MOV: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_MOV"; break;
				case RZ_ANALYSIS_OP_TYPE_OR: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_OR"; break;
				case RZ_ANALYSIS_OP_TYPE_SHR: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_SHR"; break;
				case RZ_ANALYSIS_OP_TYPE_XOR: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_XOR"; break;
				case RZ_ANALYSIS_OP_TYPE_SHL: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_SHL"; break;
				case RZ_ANALYSIS_OP_TYPE_JMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_JMP"; break;
				case RZ_ANALYSIS_OP_TYPE_ILL: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_ILL"; break;
				case RZ_ANALYSIS_OP_TYPE_AND: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_AND"; break;
				case RZ_ANALYSIS_OP_TYPE_SUB: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_SUB"; break;
				case RZ_ANALYSIS_OP_TYPE_DIV: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_DIV"; break;
				case RZ_ANALYSIS_OP_TYPE_UNK: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_UNK"; break;
				case RZ_ANALYSIS_OP_TYPE_CJMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_CJMP"; break;
				case RZ_ANALYSIS_OP_TYPE_MCJMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_MCJMP"; break;
				case RZ_ANALYSIS_OP_TYPE_UCCALL: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_UCCALL"; break;
				case RZ_ANALYSIS_OP_TYPE_MJMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_MJMP"; break;
				case RZ_ANALYSIS_OP_TYPE_NEW: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_NEW"; break;
				case RZ_ANALYSIS_OP_TYPE_IRJMP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_IRJMP"; break;
				case RZ_ANALYSIS_OP_TYPE_ADD: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_ADD"; break;
				case RZ_ANALYSIS_OP_TYPE_POP: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_POP"; break;
				case RZ_ANALYSIS_OP_TYPE_MOD: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_MOD"; break;
				case RZ_ANALYSIS_OP_TYPE_STORE: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_STORE"; break;
				case RZ_ANALYSIS_OP_TYPE_NOR: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_NOR"; break;
				case RZ_ANALYSIS_OP_TYPE_ICALL: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_ICALL"; break;
				case RZ_ANALYSIS_OP_TYPE_MUL: std::cerr << caddr << ": RZ_ANALYSIS_OP_TYPE_MUL"; break;
			}
			if(analysis_op->val && analysis_op->val != -1)
				std::cerr << " val: " << analysis_op->val << std::endl;
			else
			{
				if(analysis_op->dst)
				{
					std::cerr << " dst: ";
					char *tmp = rz_analysis_value_to_string(analysis_op->dst);
					std::cerr << tmp;
					rz_mem_free(tmp);
				}
				if(analysis_op->src[0])
				{
					std::cerr << " in0: ";
					char *tmp = rz_analysis_value_to_string(analysis_op->src[0]);
					std::cerr << tmp;
					rz_mem_free(tmp);
				}
				if(analysis_op->src[1])
				{
					std::cerr << " in1: ";
					char *tmp = rz_analysis_value_to_string(analysis_op->src[1]);
					std::cerr << tmp;
					rz_mem_free(tmp);
				}
				std::cerr << std::endl;
			}
#endif
		}

		if(mask & RZ_ANALYSIS_OP_MASK_ESIL)
			sleigh_esil(a, analysis_op, addr, data, len, pcode_slg.pcodes);

		return analysis_op->size;
	}
	catch(const LowlevelError &e)
	{
		return 0;
	}
}

/*
 * By 2020-05-24, there are 17 kinds of group of registers in SLEIGH.
 * I map them to rz_reg.h's RzRegisterType:
 * RZ_REG_TYPE_XMM:
 * RZ_REG_TYPE_SEG:
 * RZ_REG_TYPE_DRX: DEBUG
 * RZ_REG_TYPE_FPU: ST FPU
 * RZ_REG_TYPE_MMX: MMX
 * RZ_REG_TYPE_YMM: AVX VSX
 * RZ_REG_TYPE_FLG: FLAGS Flags
 * RZ_REG_TYPE_GPR: PC Cx DCR STATUS SVE CONTROL SPR SPR_UNNAMED Alt NEON
 */
static const char *rz_reg_type_arr[] = {"PC",  "Cx",          "DCR", "STATUS", "SVE",   "CONTROL",
                                "SPR", "SPR_UNNAMED", "Alt", "NEON",   "FLAGS", "Flags",
                                "AVX", "MMX",         "ST",  "FPU",    "DEBUG", "VSX", nullptr};
static const char *rz_reg_string_arr[] = {"gpr", "gpr", "gpr", "gpr", "gpr", "gpr",
                                  "gpr", "gpr", "gpr", "gpr", "flg", "flg",
                                  "ymm", "mmx", "fpu", "fpu", "drx", "ymm", nullptr};

static int get_reg_type(const std::string &name)
{
	auto p = sanalysis.reg_mapping.cbegin();
	for(; p != sanalysis.reg_mapping.cend() && p->second != name; ++p) {}
	if(p == sanalysis.reg_mapping.cend())
		throw LowlevelError("get_reg_type: reg doesn't exist.");

	const std::string &group = sanalysis.reg_group[p->first];

	if(group.empty())
		return RZ_REG_TYPE_GPR;

	for(size_t i = 0; rz_reg_type_arr[i]; i++)
	{
		if(group == rz_reg_type_arr[i])
		{
			const char *curr = rz_reg_string_arr[i];
			switch(curr[0] | curr[1] << 8)
			{
				case 'g' | 'p' << 8: return RZ_REG_TYPE_GPR;
				case 'd' | 'r' << 8: return RZ_REG_TYPE_DRX;
				case 'f' | 'p' << 8: return RZ_REG_TYPE_FPU;
				case 'm' | 'm' << 8: return RZ_REG_TYPE_MMX;
				case 'x' | 'm' << 8: return RZ_REG_TYPE_XMM;
				case 'y' | 'm' << 8: return RZ_REG_TYPE_YMM;
				case 'f' | 'l' << 8: return RZ_REG_TYPE_FLG;
				case 's' | 'e' << 8: return RZ_REG_TYPE_SEG;
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
		case ('v' | '8' << 8 | '5' << 16): // V850
				buf << "=SN\t" << "r0" << "\n" << "=BP\t" << "psw" << "\n";
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
			buf << "=SN\t" << "r6" << "\n" << "=BP\t" << "sp" << "\n";
			break;
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

static char *get_reg_profile(RzAnalysis *analysis)
{
	if(!analysis->cpu)
		return nullptr;

	ut64 length = strlen(analysis->cpu), z = 0;
	for(; z < length && analysis->cpu[z] != ':'; ++z) {}
	if(z == length)
		return nullptr;

	try
	{
		sanalysis.init(analysis->cpu, analysis->bits, analysis->big_endian, SleighAsm::getConfig(analysis));
	}
	catch(const LowlevelError &e)
	{
		std::cerr << "SleightInit " << e.explain << std::endl;
		return nullptr;
	}

	auto reg_list = sanalysis.getRegs();
	std::stringstream buf;

	for(auto p = reg_list.begin(); p != reg_list.end(); p++)
	{
		const std::string &group = sanalysis.reg_group[p->name];
		if(group.empty())
		{
			buf << "gpr\t" << sanalysis.reg_mapping[p->name] << "\t." << p->size * 8 << "\t"
			    << p->offset << "\t"
			    << "0\n";
			continue;
		}

		for(size_t i = 0;; i++)
		{
			if(!rz_reg_type_arr[i])
			{
				fprintf(stderr,
				        "analysis_ghidra.cpp:get_reg_profile() -> Get unexpected Register group(%s) "
				        "from SLEIGH, abort.",
				        group.c_str());
				return nullptr;
			}

			if(group == rz_reg_type_arr[i])
			{
				buf << rz_reg_string_arr[i] << '\t';
				break;
			}
		}

		buf << sanalysis.reg_mapping[p->name] << "\t." << p->size * 8 << "\t" << p->offset << "\t"
		    << "0\n";
	}

	if(!sanalysis.pc_name.empty())
		buf << "=PC\t" << sanalysis.reg_mapping[sanalysis.pc_name] << '\n';
	if(!sanalysis.sp_name.empty())
		buf << "=SP\t" << sanalysis.reg_mapping[sanalysis.sp_name] << '\n';

	for(unsigned i = 0; i != sanalysis.arg_names.size() && i <= 9; ++i)
		buf << "=A" << i << '\t' << sanalysis.reg_mapping[sanalysis.arg_names[i]] << '\n';

	for(unsigned i = 0; i != sanalysis.ret_names.size() && i <= 3; ++i)
		buf << "=R" << i << '\t' << sanalysis.reg_mapping[sanalysis.ret_names[i]] << '\n';

	ut64 pp = 0;
	string arch = sanalysis.sleigh_id.substr(pp, sanalysis.sleigh_id.find(':', pp) - pp);
	pp = sanalysis.sleigh_id.find(':', pp) + 1;
	bool little = sanalysis.sleigh_id.substr(pp, sanalysis.sleigh_id.find(':', pp) - pp) == "LE";
	pp = sanalysis.sleigh_id.find(':', pp) + 1;
	int bits = std::stoi(sanalysis.sleigh_id.substr(pp, sanalysis.sleigh_id.find(':', pp) - pp));
	pp = sanalysis.sleigh_id.find(':', pp) + 1;

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

static bool esil_pushnum_float(RzAnalysisEsil *esil, long double num)
{
	char str[64];
	snprintf(str, sizeof(str) - 1, "%.*LeF", DECIMAL_DIG, num);
	return rz_analysis_esil_push(esil, str);
}

static int esil_get_parm_type_float(RzAnalysisEsil *esil, const char *str)
{
	int len, i;

	if(!str || !(len = strlen(str)))
		return RZ_ANALYSIS_ESIL_PARM_INVALID;

	if((str[len - 1] == 'F') && (str[1] == '.' || (str[2] == '.' && str[0] == '-')))
		return ESIL_PARM_FLOAT;
	if(!strcmp(str, "nanF") || !strcmp(str, "infF") || !strcmp(str, "-nanF") ||
	   !strcmp(str, "-infF"))
		return ESIL_PARM_FLOAT;

	return RZ_ANALYSIS_ESIL_PARM_INVALID;
}

static long double esil_get_double(RzReg *reg, RzRegItem *item)
{
	RzRegSet *regset;
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

static bool esil_set_double(RzReg *reg, RzRegItem *item, long double value)
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
		rz_mem_copybits(reg->regset[item->arena].arena->bytes + BITS2BYTES(item->offset), src,
		               item->size);
		return true;
	}
	eprintf("esil_set_double: Cannot set register.");
	return false;
}

static int esil_get_parm_float(RzAnalysisEsil *esil, const char *str, long double *num)
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
			// *num = rz_num_get (NULL, str);
			sscanf(str, "%LfF", num);
			ret = 1;
			break;
		case RZ_ANALYSIS_ESIL_PARM_REG:
		{
			RzRegItem *reg = rz_reg_get(esil->analysis->reg, str, get_reg_type(str));
			if(reg)
			{
				*num = esil_get_double(esil->analysis->reg, reg);
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

static bool sleigh_esil_consts_pick(RzAnalysisEsil *esil)
{
	if(!esil || !esil->stack)
		return false;

	char *idx = rz_analysis_esil_pop(esil);
	ut64 i;
	int ret = false;

	if(RZ_ANALYSIS_ESIL_PARM_REG == rz_analysis_esil_get_parm_type(esil, idx))
	{
		ERR("sleigh_esil_consts_pick: argument is consts only.");
		goto end;
	}
	if(!idx || !rz_analysis_esil_get_parm(esil, idx, &i))
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
	if(!rz_analysis_esil_push(esil, esil->stack[esil->stackptr - i]))
	{
		ERR("ESIL stack is full.");
		esil->trap = 1;
		esil->trap_code = 1;
		goto end;
	}
	ret = true;

end:
	rz_mem_free(idx);
	return ret;
}

static bool sleigh_esil_is_nan(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = rz_analysis_esil_pop(esil);
	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
			ret = rz_analysis_esil_pushnum(esil, isnan(s));
		else
			ERR("sleigh_esil_is_nan: invalid parameters.");

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_is_nan: fail to get argument from stack.");

	return ret;
}

static bool sleigh_esil_int_to_float(RzAnalysisEsil *esil)
{
	bool ret = false;
	st64 s;
	char *src = rz_analysis_esil_pop(esil);
	if(src)
	{
		if(rz_analysis_esil_get_parm(esil, src, (ut64 *)&s))
			ret = esil_pushnum_float(esil, (long double)s * 1.0);
		else
			ERR("sleigh_esil_int_to_float: invalid parameters.");

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_int_to_float: fail to get argument from stack.");

	return ret;
}

static bool sleigh_esil_float_to_int(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = rz_analysis_esil_pop(esil);
	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
		{
			if(isnan(s) || isinf(s))
				ERR("sleigh_esil_float_to_int: nan or inf detected.");
			ret = rz_analysis_esil_pushnum(esil, (st64)(s));
		}
		else
			ERR("sleigh_esil_float_to_int: invalid parameters.");

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_to_int: fail to get argument from stack.");

	return ret;
}

static bool sleigh_esil_float_to_float(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double d;
	ut64 s = 0;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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

	if(rz_analysis_esil_get_parm(esil, src, &s) && esil_get_parm_float(esil, dst, &d))
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
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_cmp(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
			ret = rz_analysis_esil_pushnum(esil, 0);
		else
			ret = rz_analysis_esil_pushnum(esil, fabs(s - d) < std::numeric_limits<long double>::epsilon());
	}
	else
		ERR("sleigh_esil_float_cmp: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_cmp(RzAnalysisEsil *esil)
{
	ut64 num, num2;
	bool ret = false;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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

	if(rz_analysis_esil_get_parm(esil, dst, &num) && rz_analysis_esil_get_parm(esil, src, &num2))
	{
		esil->old = num;
		esil->cur = num - num2;
		ret = true;
		esil->lastsz = 64;
		rz_analysis_esil_pushnum(esil, num == num2);
	}
	else
		ERR("sleigh_esil_cmp: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_negcmp(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
			ret = rz_analysis_esil_pushnum(esil, 0);
		else
			ret = rz_analysis_esil_pushnum(esil, fabs(s - d) >= std::numeric_limits<long double>::epsilon());
	}
	else
		ERR("sleigh_esil_float_negcmp: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_less(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
			ret = rz_analysis_esil_pushnum(esil, 0);
		else
			ret = rz_analysis_esil_pushnum(esil, s < d);
	}
	else
		ERR("sleigh_esil_float_less: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_lesseq(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
			ret = rz_analysis_esil_pushnum(esil, 0);
		else
			ret = rz_analysis_esil_pushnum(esil, s <= d);
	}
	else
		ERR("sleigh_esil_float_lesseq: invalid parameters.");


end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_add(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
				ret = esil_pushnum_float(esil, NAN);
			else
				ret = esil_pushnum_float(esil, s + d);
		}
	}
	else
		ERR("sleigh_esil_float_add: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_sub(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
				ret = esil_pushnum_float(esil, NAN);
			else
				ret = esil_pushnum_float(esil, d - s);
		}
	}
	else
		ERR("sleigh_esil_float_sub: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_mul(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
				ret = esil_pushnum_float(esil, NAN);
			else
				ret = esil_pushnum_float(esil, s * d);
		}
	}
	else
		ERR("sleigh_esil_float_mul: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_div(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

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
				ret = esil_pushnum_float(esil, NAN);
			else
				ret = esil_pushnum_float(esil, d / s);
		}
	}
	else
		ERR("sleigh_esil_float_div: invalid parameters.");

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_float_neg(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = rz_analysis_esil_pop(esil);

	if(src)
	{
		if(esil_get_parm_float(esil, src, &s))
			ret = esil_pushnum_float(esil, -s);
		else
			ERR("sleigh_esil_float_neg: invalid parameters.");

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_neg: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_ceil(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = rz_analysis_esil_pop(esil);

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

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_ceil: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_floor(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = rz_analysis_esil_pop(esil);

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

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_floor: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_round(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = rz_analysis_esil_pop(esil);

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

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_round: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_float_sqrt(RzAnalysisEsil *esil)
{
	bool ret = false;
	long double s;
	char *src = rz_analysis_esil_pop(esil);

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

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_float_sqrt: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_popcount(RzAnalysisEsil *esil)
{
	bool ret = false;
	ut64 s, res = 0;
	char *src = rz_analysis_esil_pop(esil);

	if(src)
	{
		if(src && rz_analysis_esil_get_parm(esil, src, &s))
		{
			while(s)
			{
				s &= s - 1;
				++res;
			}
			ret = rz_analysis_esil_pushnum(esil, res);
		}
		else
			ERR("sleigh_esil_popcount: invalid parameters.");

		rz_mem_free(src);
	}
	else
		ERR("sleigh_esil_popcount: fail to get element from stack.");

	return ret;
}

static bool sleigh_esil_signext(RzAnalysisEsil *esil)
{
	// From https://github.com/rizinorg/rizin/pull/17436/
	ut64 src, dst;

	char *p_src = rz_analysis_esil_pop(esil);
	if(!p_src)
		return false;

	if(!rz_analysis_esil_get_parm(esil, p_src, &src))
	{
		ERR("sleigh_esil_signext: invalid parameters.");
		rz_mem_free(p_src);
		return false;
	}
	else
		rz_mem_free(p_src);

	char *p_dst = rz_analysis_esil_pop(esil);
	if(!p_dst)
		return false;

	if(!rz_analysis_esil_get_parm(esil, p_dst, &dst))
	{
		ERR("sleigh_esil_signext: invalid parameters.");
		rz_mem_free(p_dst);
		return false;
	}
	else
		rz_mem_free(p_dst);

	ut64 m = 0;
	if(dst < 64)
		m = 1ULL << (dst - 1);

	// dst = (dst & ((1U << src_bit) - 1)); // clear upper bits
	return rz_analysis_esil_pushnum(esil, ((src ^ m) - m));
}

static void sleigh_reg_set_float(RzReg *reg, const char *name, int type, bool F)
{
	RzRegItem *tmp = rz_reg_get(reg, name, type);
	if(tmp)
		tmp->is_float = F;
}

static bool sleigh_reg_get_float(RzReg *reg, const char *name, int type)
{
	RzRegItem *tmp = rz_reg_get(reg, name, type);
	return tmp ? tmp->is_float : false;
}

// All register's value will be resolved immediately thanks to NUM.
static bool sleigh_esil_reg_num(RzAnalysisEsil *esil)
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
	if(!esil->analysis || !esil->analysis->reg)
		return false;

	char *name = rz_analysis_esil_pop(esil);
	ut64 i;

	if(name)
	{
		if(RZ_ANALYSIS_ESIL_PARM_REG != rz_analysis_esil_get_parm_type(esil, name))
			ERR("sleigh_esil_reg_num: stack top isn't register.");

		is_float = sleigh_reg_get_float(esil->analysis->reg, name, get_reg_type(name));
		if(is_float)
		{
			RzRegItem *ri = rz_reg_get(esil->analysis->reg, name, get_reg_type(name));
			if (ri)
			{
				long double res = esil_get_double(esil->analysis->reg, ri);
				ret = esil_pushnum_float(esil, res);
			}
		}
		else
		{
			rz_analysis_esil_get_parm(esil, name, &i);
			ret = rz_analysis_esil_pushnum(esil, i);
		}

		rz_mem_free(name);
	}
	else
		ERR("sleigh_esil_reg_num: fail to get element from stack.");

	return ret;
}

static bool isnum(RzAnalysisEsil *esil, const char *str, ut64 *num)
{
	if(!esil || !str)
	{
		return false;
	}
	if(IS_DIGIT(*str))
	{
		if(num)
		{
			*num = rz_num_get(NULL, str);
		}
		return true;
	}
	if(num)
	{
		*num = 0;
	}
	return false;
}

static bool ispackedreg(RzAnalysisEsil *esil, const char *str)
{
	RzRegItem *ri = rz_reg_get(esil->analysis->reg, str, -1);
	return ri? ri->packed_size > 0: false;
}

static bool isregornum(RzAnalysisEsil *esil, const char *str, ut64 *num)
{
	if(!rz_analysis_esil_reg_read(esil, str, num, NULL))
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

static ut8 esil_internal_sizeof_reg(RzAnalysisEsil *esil, const char *r)
{
	rz_return_val_if_fail(esil && esil->analysis && esil->analysis->reg && r, 0);
	RzRegItem *ri = rz_reg_get(esil->analysis->reg, r, -1);
	return ri? ri->size: 0;
}

static int rz_analysis_esil_reg_read_nocallback(RzAnalysisEsil *esil, const char *regname, ut64 *num,
                                           int *size)
{
	int ret;
	int (*old_hook_reg_read)(rz_analysis_esil_t *, const char *, long long unsigned int *, int *) =
	    esil->cb.hook_reg_read;
	esil->cb.hook_reg_read = NULL;
	ret = rz_analysis_esil_reg_read(esil, regname, num, size);
	esil->cb.hook_reg_read = old_hook_reg_read;
	return ret;
}

static bool esil_eq(RzAnalysisEsil *esil)
{
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if(!src || !dst)
	{
		ERR("esil_eq: Missing elements in esil stack.");
		return false;
	}
	if(ispackedreg(esil, dst))
	{
		char *src2 = rz_analysis_esil_pop(esil);
		char *newreg = rz_str_newf("%sl", dst);
		if(rz_analysis_esil_get_parm(esil, src2, &num2))
			ret = rz_analysis_esil_reg_write(esil, newreg, num2);

		rz_mem_free(newreg);
		rz_mem_free(src2);
		goto beach;
	}

	if(rz_analysis_esil_reg_read_nocallback(esil, dst, &num, NULL))
	{
		if(rz_analysis_esil_get_parm(esil, src, &num2))
		{
			ret = rz_analysis_esil_reg_write(esil, dst, num2);
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
	rz_mem_free(src);
	rz_mem_free(dst);
	return ret;
}

static bool esil_peek_n(RzAnalysisEsil *esil, int bits)
{
	if(bits & 7)
		return false;

	bool ret = false;
	char res[32];
	ut64 addr;
	ut32 bytes = bits / 8;
	char *dst = rz_analysis_esil_pop(esil);
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
			ret = rz_analysis_esil_mem_read(esil, addr, a, bytes);
			ut64 b = rz_read_ble64(&a, 0);    // esil->analysis->big_endian);
			ut64 c = rz_read_ble64(&a[8], 0); // esil->analysis->big_endian);
			snprintf(res, sizeof(res), "0x%" PFMT64x, b);
			rz_analysis_esil_push(esil, res);
			snprintf(res, sizeof(res), "0x%" PFMT64x, c);
			rz_analysis_esil_push(esil, res);
			rz_mem_free(dst);
			return ret;
		}
		ut64 bitmask = genmask(bits - 1);
		ut8 a[sizeof(ut64)] = {0};
		ret = !!rz_analysis_esil_mem_read(esil, addr, a, bytes);
		ut64 b = rz_read_ble64(a, esil->analysis->big_endian);

		snprintf(res, sizeof(res), "0x%" PFMT64x, b & bitmask);
		rz_analysis_esil_push(esil, res);
		esil->lastsz = bits;
	}
	rz_mem_free(dst);
	return ret;
}

static bool esil_poke_n(RzAnalysisEsil *esil, int bits)
{
	ut64 bitmask = genmask(bits - 1);
	ut64 num, num2, addr;
	ut8 b[8] = {0};
	ut64 n;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	int bytes = RZ_MIN(sizeof(b), bits / 8);
	if(bits % 8)
	{
		rz_mem_free(src);
		rz_mem_free(dst);
		return false;
	}
	bool ret = false;
	// eprintf ("GONA POKE %d src:%s dst:%s\n", bits, src, dst);
	char *src2 = NULL;
	if(src && rz_analysis_esil_get_parm(esil, src, &num))
	{
		if(dst && rz_analysis_esil_get_parm(esil, dst, &addr))
		{
			if(bits == 128)
			{
				src2 = rz_analysis_esil_pop(esil);
				if(src2 && rz_analysis_esil_get_parm(esil, src2, &num2))
				{
					rz_write_ble(b, num, esil->analysis->big_endian, 64);
					ret = rz_analysis_esil_mem_write(esil, addr, b, bytes);
					if(ret == 0)
					{
						rz_write_ble(b, num2, esil->analysis->big_endian, 64);
						ret = rz_analysis_esil_mem_write(esil, addr + 8, b, bytes);
					}
					goto out;
				}
				ret = -1;
				goto out;
			}
			// this is a internal peek performed before a poke
			// we disable hooks to avoid run hooks on internal peeks
			int (*oldhook)(rz_analysis_esil_t *, long long unsigned int, unsigned char *, int) =
			    esil->cb.hook_mem_read;
			esil->cb.hook_mem_read = NULL;
			rz_analysis_esil_mem_read(esil, addr, b, bytes);
			esil->cb.hook_mem_read = oldhook;
			n = rz_read_ble64(b, esil->analysis->big_endian);
			esil->old = n;
			esil->cur = num;
			esil->lastsz = bits;
			num = num & bitmask;
			rz_write_ble(b, num, esil->analysis->big_endian, bits);
			ret = rz_analysis_esil_mem_write(esil, addr, b, bytes);
		}
	}
out:
	rz_mem_free(src2);
	rz_mem_free(src);
	rz_mem_free(dst);
	return ret;
}

static bool sleigh_esil_eq(RzAnalysisEsil *esil)
{
	bool ret = false;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	long double tmp;

	if(!src)
	{
		ERR("sleigh_esil_eq: fail to get argument from stack.");
		return false;
	}
	if(!dst)
	{
		ERR("sleigh_esil_eq: fail to get argument from stack.");
		rz_mem_free(src);
		return false;
	}

	if(ESIL_PARM_FLOAT == esil_get_parm_type_float(esil, src))
	{
		RzRegItem *ri = rz_reg_get(esil->analysis->reg, dst, get_reg_type(dst));
		if(ri)
		{
			esil_get_parm_float(esil, src, &tmp);
			ret = esil_set_double(esil->analysis->reg, ri, tmp);
			sleigh_reg_set_float(esil->analysis->reg, dst, get_reg_type(dst), true);
		}
	}
	else
	{
		rz_analysis_esil_push(esil, src);
		rz_analysis_esil_push(esil, dst);
		ret = esil_eq(esil);
		sleigh_reg_set_float(esil->analysis->reg, dst, get_reg_type(dst), false);
	}

	rz_mem_free(dst);
	rz_mem_free(src);

	return ret;
}

static std::unordered_set<uintm> float_mem;

static bool sleigh_esil_peek4(RzAnalysisEsil *esil) // Read out
{
	ut64 addr;
	char *src = rz_analysis_esil_pop(esil);
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
		rz_mem_free(src);
		return true;
	}

	if(float_mem.find(addr) != float_mem.end())
	{
		float a;
		ret = !!rz_analysis_esil_mem_read(esil, addr, (ut8 *)&a, 4);
		snprintf(str, sizeof(str) - 1, "%.*LeF", DECIMAL_DIG, (long double)a);
		rz_analysis_esil_push(esil, str);
		esil->lastsz = 32;
	}
	else
	{
		rz_analysis_esil_push(esil, src);
		ret = esil_peek_n(esil, 32);
	}

	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_peek8(RzAnalysisEsil *esil)
{
	ut64 addr;
	char *src = rz_analysis_esil_pop(esil);
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
		rz_mem_free(src);
		return true;
	}

	if(float_mem.find(addr) != float_mem.end())
	{
		double a;
		ret = !!rz_analysis_esil_mem_read(esil, addr, (ut8 *)&a, 8);
		snprintf(str, sizeof(str) - 1, "%.*LeF", DECIMAL_DIG, (long double)a);
		rz_analysis_esil_push(esil, str);
		esil->lastsz = 64;
	}
	else
	{
		rz_analysis_esil_push(esil, src);
		ret = esil_peek_n(esil, 64);
	}

	rz_mem_free(src);
	return ret;
}

static bool sleigh_esil_poke4(RzAnalysisEsil *esil)
{
	bool ret = false;
	ut64 addr;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
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
		ret = rz_analysis_esil_mem_write(esil, addr, (ut8 *)&res, 4);
		float_mem.insert(addr);
	}
	else
	{
		rz_analysis_esil_push(esil, src);
		rz_analysis_esil_push(esil, dst);
		ret = esil_poke_n(esil, 32);
		auto iter = float_mem.find(addr);
		if(iter != float_mem.end())
			float_mem.erase(iter);
	}

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);

	return ret;
}

static bool sleigh_esil_poke8(RzAnalysisEsil *esil)
{
	bool ret = false;
	ut64 addr;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
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
		ret = rz_analysis_esil_mem_write(esil, addr, (ut8 *)&res, 8);
		float_mem.insert(addr);
	}
	else
	{
		rz_analysis_esil_push(esil, src);
		rz_analysis_esil_push(esil, dst);
		ret = esil_poke_n(esil, 64);
		auto iter = float_mem.find(addr);
		if(iter != float_mem.end())
			float_mem.erase(iter);
	}

end2:
	rz_mem_free(dst);
end1:
	rz_mem_free(src);

	return ret;
}

static int esil_sleigh_init(RzAnalysisEsil *esil)
{
	if(!esil)
		return false;

	float_mem.clear();

	// Only consts-only version PICK will meet my demand
	rz_analysis_esil_set_op(esil, "PICK", sleigh_esil_consts_pick, 1, 0, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	// Reg -> Stack
	rz_analysis_esil_set_op(esil, "NUM", sleigh_esil_reg_num, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "NAN", sleigh_esil_is_nan, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	// Stack -> Reg
	rz_analysis_esil_set_op(esil, "=", sleigh_esil_eq, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "I2F", sleigh_esil_int_to_float, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F2I", sleigh_esil_float_to_int, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F2F", sleigh_esil_float_to_float, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	// Stack -> Mem
	rz_analysis_esil_set_op(esil, "=[4]", sleigh_esil_poke4, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "=[8]", sleigh_esil_poke8, 0, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	// Mem -> Stack
	rz_analysis_esil_set_op(esil, "[4]", sleigh_esil_peek4, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "[8]", sleigh_esil_peek8, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F==", sleigh_esil_float_cmp, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "==", sleigh_esil_cmp, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F!=", sleigh_esil_float_negcmp, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F<", sleigh_esil_float_less, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F<=", sleigh_esil_float_lesseq, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F+", sleigh_esil_float_add, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F-", sleigh_esil_float_sub, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F*", sleigh_esil_float_mul, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "F/", sleigh_esil_float_div, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "-F", sleigh_esil_float_neg, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "CEIL", sleigh_esil_float_ceil, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "FLOOR", sleigh_esil_float_floor, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "ROUND", sleigh_esil_float_round, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "SQRT", sleigh_esil_float_sqrt, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "SIGN", sleigh_esil_signext, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	rz_analysis_esil_set_op(esil, "POPCOUNT", sleigh_esil_popcount, 1, 2, RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);

	return true;
}

static int esil_sleigh_fini(RzAnalysisEsil *esil)
{
	float_mem.clear();
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_ghidra = {
	/* .name = */ "ghidra",
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
	/* .analysis_mask = */ nullptr,
	/* .preludes = */ nullptr,
	/* .address_bits = */ nullptr,
	/* .op = */ &sleigh_op,
	/* .get_reg_profile = */ &get_reg_profile,
	/* .esil_init = */ esil_sleigh_init,
	/* .esil_post_loop = */ nullptr,
	/* .esil_trap = */ nullptr,
	/* .esil_fini = */ esil_sleigh_fini,
};

#ifndef CORELIB
extern "C" {
RZ_API RzLibStruct rizin_plugin = {
	/* .type = */ RZ_LIB_TYPE_ANALYSIS,
	/* .data = */ &rz_analysis_plugin_ghidra,
	/* .version = */ RZ_VERSION,
	/* .free = */ nullptr,
};
}
#endif
