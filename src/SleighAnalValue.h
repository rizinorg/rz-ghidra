/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHANALVALUE_H
#define R2GHIDRA_SLEIGHANALVALUE_H

#include "SleighAsm.h"

struct SleighAnalValue: public RAnalValue
{
public:
	SleighAnalValue()
	{
		access = RAnalValueAccess(0);
		absolute = memref = base = delta = imm = mul = 0;
		seg = reg = regdelta = nullptr;
	}

	static SleighAnalValue resolve_arg(RAnal *anal, const PcodeOperand *arg);

	static std::vector<SleighAnalValue> resolve_out(RAnal *anal,
                                           std::vector<Pcodeop>::const_iterator curr_op,
                                           std::vector<Pcodeop>::const_iterator end_op,
                                           const PcodeOperand *arg);

	bool is_valid() const { return absolute != -1; }
	bool is_imm() const { return type == R_ANAL_VAL_IMM; }
	bool is_reg() const { return type == R_ANAL_VAL_REG; }
	bool is_mem() const { return type == R_ANAL_VAL_MEM; }

	void invalid() { absolute = -1; }
	void mem(uint4 size);
	RAnalValue *dup() const;

private:
	static RAnalValueType type_from_values(const SleighAnalValue &in0, const SleighAnalValue &in1);

	template<typename T>
	static inline T inner_max(T foo, T bar)
	{
		return foo > bar? foo: bar;
	}
};

#endif // R2GHIDRA_SLEIGHANALVALUE_H