// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_SLEIGHANALVALUE_H
#define RZ_GHIDRA_SLEIGHANALVALUE_H

#include "SleighAsm.h"

struct SleighAnalValue: public RzAnalValue
{
public:
	SleighAnalValue()
	{
		access = RzAnalValueAccess(0);
		absolute = memref = base = delta = imm = mul = 0;
		seg = reg = regdelta = nullptr;
	}

	static SleighAnalValue resolve_arg(RzAnal *anal, const PcodeOperand *arg);

	static std::vector<SleighAnalValue> resolve_out(RzAnal *anal,
                                           std::vector<Pcodeop>::const_iterator curr_op,
                                           std::vector<Pcodeop>::const_iterator end_op,
                                           const PcodeOperand *arg);

	bool is_valid() const { return absolute != -1; }
	bool is_imm() const { return type == RZ_ANAL_VAL_IMM; }
	bool is_reg() const { return type == RZ_ANAL_VAL_REG; }
	bool is_mem() const { return type == RZ_ANAL_VAL_MEM; }

	void invalid() { absolute = -1; }
	void mem(uint4 size);
	RzAnalValue *dup() const;

private:
	static RzAnalValueType type_from_values(const SleighAnalValue &in0, const SleighAnalValue &in1);

	template<typename T>
	static inline T inner_max(T foo, T bar)
	{
		return foo > bar? foo: bar;
	}
};

#endif // RZ_GHIDRA_SLEIGHANALVALUE_H