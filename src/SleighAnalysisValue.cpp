// SPDX-License-Identifier: LGPL-3.0-or-later

#include "SleighAnalysisValue.h"

RzAnalysisValueType SleighAnalysisValue::type_from_values(const SleighAnalysisValue &in0, const SleighAnalysisValue &in1)
{
	RzAnalysisValueType res;

	if(in0.is_mem() || in1.is_mem())
		res = RZ_ANALYSIS_VAL_MEM;
	else if(in0.is_reg() || in1.is_reg())
		res = RZ_ANALYSIS_VAL_REG;
	else
		res = RZ_ANALYSIS_VAL_IMM;
	
	return res;
}

SleighAnalysisValue SleighAnalysisValue::resolve_arg(RzAnalysis *analysis, const PcodeOperand *arg)
{
	SleighAnalysisValue res;

	if(arg->is_const())
	{
		res.type = RZ_ANALYSIS_VAL_IMM;
		res.imm = arg->number;
	}
	else if(arg->is_reg())
	{
		res.type = RZ_ANALYSIS_VAL_REG;
		res.reg = rz_reg_get(analysis->reg, arg->name.c_str(), RZ_REG_TYPE_ALL);
	}
	else if(arg->is_ram())
	{
		res.type = RZ_ANALYSIS_VAL_MEM;
		res.base = arg->offset;
		res.memref = arg->size;
	}
	else
	{ // PcodeOperand::UNIQUE
		const Pcodeop *curr_op = ((UniquePcodeOperand *)arg)->def;
		SleighAnalysisValue in0, in1;

		if(curr_op->input0)
		{
			in0 = resolve_arg(analysis, curr_op->input0);
			if(!in0.is_valid())
				return in0;
		}
		if(curr_op->input1)
		{
			in1 = resolve_arg(analysis, curr_op->input1);
			if(!in1.is_valid())
				return in1;
		}

		switch(curr_op->type)
		{
			case CPUI_INT_ZEXT:
			case CPUI_INT_SEXT:
			case CPUI_SUBPIECE:
			case CPUI_COPY:
			{
				res = in0;
				break;
			}

			case CPUI_LOAD:
			{
				res = in1;
				if(res.is_imm())
				{
					res.base = res.imm;
					res.imm = 0;
				}
				res.type = RZ_ANALYSIS_VAL_MEM;
				res.memref = curr_op->output->size;
				break;
			}

			case CPUI_INT_ADD:
			case CPUI_INT_SUB:
			{
				res.type = type_from_values(in0, in1);

				res.memref = inner_max(in0.memref, in1.memref);
				if(res.is_imm())
					res.imm = (curr_op->type == CPUI_INT_ADD)? in0.imm + in1.imm : in0.imm - in1.imm;
				else
				{
					res.base = in0.imm + in0.base;
					res.base += (curr_op->type == CPUI_INT_ADD)? (in1.imm + in1.base) : -(in1.imm + in1.base);
				}
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
				res.type = type_from_values(in0, in1);

				res.memref = inner_max(in0.memref, in1.memref);
				if(res.is_imm())
				{
					res.imm = in0.imm * in1.imm;
				}
				else if(in0.is_imm() && in1.is_mem())
				{
					res.mul = in0.imm;
					res.delta = in1.base;
				}
				else if(in0.is_mem() && in1.is_imm())
				{
					res.mul = in1.imm;
					res.delta = in0.base;
				}
				else if(in0.is_imm() && in1.is_reg())
				{
					res.mul = in0.imm;
					res.regdelta = in1.reg;
				}
				else if(in0.is_reg() && in1.is_imm())
				{
					res.mul = in1.imm;
					res.regdelta = in0.reg;
				}
				else
					res.invalid();

				break;
			}

			case CPUI_INT_AND:
			{
				// Should only happen when const need some modification.
				res.type = in0.type;
				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.is_imm() && in1.is_imm())
					res.imm = in0.imm & in1.imm;
				else
					res.invalid();
				break;
			}

			case CPUI_INT_OR:
			{
				// Should only happen when const need some modification.
				res.type = in0.type;
				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.is_imm() && in1.is_imm())
					res.imm = in0.imm | in1.imm;
				else
					res.invalid();
				break;
			}

			case CPUI_INT_XOR:
			{
				// Should only happen when const need some modification.
				res.type = in0.type;
				res.memref = inner_max(in0.memref, in1.memref);
				if(in0.is_imm() && in1.is_imm())
					res.imm = in0.imm ^ in1.imm;
				else
					res.invalid();
				break;
			}

			default: 
				res.invalid();
				break;
		}
	}

	return res;
}

std::vector<SleighAnalysisValue> SleighAnalysisValue::resolve_out(RzAnalysis *analysis,
                                          std::vector<Pcodeop>::const_iterator curr_op,
                                          std::vector<Pcodeop>::const_iterator end_op,
                                          const PcodeOperand *arg)
{
	std::vector<SleighAnalysisValue> res;
	SleighAnalysisValue tmp;

	if(arg->is_const())
	{
		tmp.type = RZ_ANALYSIS_VAL_IMM;
		tmp.imm = arg->number;
		res.push_back(tmp);
	}
	else if(arg->is_reg())
	{
		tmp.type = RZ_ANALYSIS_VAL_REG;
		tmp.reg = rz_reg_get(analysis->reg, arg->name.c_str(), RZ_REG_TYPE_ALL);
		res.push_back(tmp);
	}
	else if(arg->is_ram())
	{
		tmp.type = RZ_ANALYSIS_VAL_MEM;
		tmp.base = arg->offset;
		tmp.memref = arg->size;
		res.push_back(tmp);
	}
	else
	{
		for(auto iter = ++curr_op; iter != end_op; ++iter)
		{
			if(iter->type == CPUI_STORE)
			{
				if(iter->output && *iter->output == *arg && iter->input1)
				{
					tmp = resolve_arg(analysis, iter->input1);
					if(tmp.is_valid())
					{
						tmp.mem(iter->output->size);
						res.push_back(tmp);
					}
				}
			}
			else
			{
				if((iter->input0 && *iter->input0 == *arg) ||
				   (iter->input1 && *iter->input1 == *arg))
				{
					if(iter->output && iter->output->is_reg())
					{
						tmp = SleighAnalysisValue();
						tmp.type = RZ_ANALYSIS_VAL_REG;
						tmp.reg = rz_reg_get(analysis->reg, iter->output->name.c_str(), RZ_REG_TYPE_ALL);
						res.push_back(tmp);
					}
				}
			}
		}
	}

	return res;
}

void SleighAnalysisValue::mem(uint4 size)
{
	if(is_mem())
		return;

	if(is_imm())
	{
		base = imm;
		imm = 0;
	}
	memref = size;
	type = RZ_ANALYSIS_VAL_MEM;
}

RzAnalysisValue *SleighAnalysisValue::dup() const
{
	RzAnalysisValue *to = rz_analysis_value_new();
	if(!to)
		return to;

	*to = (RzAnalysisValue)*this;
	return to;
}
