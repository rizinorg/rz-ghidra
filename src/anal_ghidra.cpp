/* radare - LGPL - Copyright 2020 - FXTi */

#include <r_lib.h>
#include <r_anal.h>
#include <algorithm>
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

static std::vector<std::string> string_split(const std::string& s, const char& delim = ' ') {
	std::vector<std::string> tokens;
    size_t lastPos = s.find_first_not_of(delim, 0);
    size_t pos = s.find(delim, lastPos);
    while (lastPos != string::npos) {
        tokens.emplace_back(s.substr(lastPos, pos - lastPos));
        lastPos = s.find_first_not_of(delim, pos);
        pos = s.find(delim, lastPos);
    }
	return tokens;
}

static std::string string_trim(std::string s) {
    if (!s.empty()) {
    	s.erase(0,s.find_first_not_of(" "));
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
			for (auto iter = body.cbegin(); iter != body.cend(); ++iter)
				if (*iter != '[' && *iter != ']')
					args.push_back(*iter);
		}
};

static bool isOperandInteresting(const PcodeOperand *arg, std::vector<std::string> &regs, std::unordered_set<PcodeOperand, PcodeOperand> &mid_vars) {
	if (arg) {
		if (arg->type == PcodeOperand::REGISTER) {
			for (auto iter = regs.cbegin(); iter != regs.cend(); ++iter)
				if (*iter == arg->name)
					return true;
		}

		if (arg->type == PcodeOperand::UNIQUE)
			return mid_vars.find(*arg) != mid_vars.end();
	}
	return false;
}

static bool anal_type_SAR(RAnalOp *anal_op, const std::vector<const Pcodeop *> filtered_ops) {
	for (auto iter = filtered_ops.cbegin(); iter != filtered_ops.cend(); ++iter) {
		if ((*iter)->type == CPUI_INT_SRIGHT) {
			anal_op->type = R_ANAL_OP_TYPE_SAR;
			/*
			op->dst = parsed_operands[0].value;
			op->src[0] = parsed_operands[1].value;
			op->src[1] = parsed_operands[2].value;
			*/

			return true;
		}
	}

	return false;
}

static void anal_type(RAnalOp *anal_op, PcodeSlg &pcode_slg, InnerAssemblyEmit &assem)
{
	std::vector<std::string> args = string_split(assem.args, ',');
	std::transform(args.begin(), args.end(), args.begin(), string_trim);
	std::unordered_set<PcodeOperand, PcodeOperand> mid_vars;
	std::vector<const Pcodeop *> filtered_ops;

	for (auto pco = pcode_slg.pcodes.cbegin(); pco != pcode_slg.pcodes.cend(); ++pco) {
		if (pco->type == CPUI_STORE) {
			if (isOperandInteresting(pco->input1, args, mid_vars) || isOperandInteresting(pco->output, args, mid_vars)) {
				if (pco->input1 && pco->input1->type == PcodeOperand::UNIQUE)
					mid_vars.insert(*pco->input1);
			} else
				continue;
		} else {
			if (isOperandInteresting(pco->input0, args, mid_vars) || isOperandInteresting(pco->input1, args, mid_vars)) {
				if (pco->output && pco->output->type == PcodeOperand::UNIQUE)
					mid_vars.insert(*pco->output);
			} else
				continue;
		}

		filtered_ops.push_back(&(*pco));
		std::cerr << "0x" << hex << anal_op->addr << ": " << *pco << std::endl;
	}

	// Filter work is done. Process now.
	anal_op->type = R_ANAL_OP_TYPE_UNK;

	anal_type_SAR(anal_op, filtered_ops);
}

static char *getIndirectReg(SleighInstruction &ins, bool &isRefed) {
	VarnodeData data = ins.getIndirectInvar();
	isRefed = data.size & 0x80000000;
	if (isRefed)
		data.size &= ~0x80000000;

	AddrSpace *space = data.space;
	if(space->getName() == "register")
		return strdup(space->getTrans()->getRegisterName(data.space, data.offset, data.size).c_str());
	else
		return nullptr;
}

static int index_of_unique(const std::vector<PcodeOperand *> &esil_stack, const PcodeOperand *arg) {
	int index = 1;
	for (auto iter = esil_stack.crbegin(); iter != esil_stack.crend(); ++iter, ++index)
		if (**iter == *arg)
			return index;
	
	return -1;
}

static void sleigh_esil(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, std::vector<Pcodeop> &Pcodes) {
	std::vector<PcodeOperand *> esil_stack;
	stringstream ss;
	auto print_if_unique = [&esil_stack, &ss](const PcodeOperand *arg) -> bool {
		if (arg->is_unique()) {
			int index = index_of_unique(esil_stack, arg);
			if (-1 == index)
				throw LowlevelError("print_unique: Can't find required unique varnodes in stack.");

			ss << index << ",PICK";
			return true;
		} else 
			return false;
	};
	auto push_stack = [&esil_stack](PcodeOperand *arg) { esil_stack.push_back(arg); };

	for (auto iter = Pcodes.cbegin(); iter != Pcodes.cend(); ++iter) {
		switch (iter->type) {
			case CPUI_INT_SEXT:
			case CPUI_INT_ZEXT: /* do nothing */ break;

			case CPUI_COPY: {
				if (iter->input0 && iter->output) {
					ss << ",";
					if (!print_if_unique(iter->input0)) 
						ss << *iter->input0;
						
					if (iter->output->is_unique()) 
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_LOAD: {
				if (iter->input0 && iter->input1 && iter->output) {
					ss << ",";
					if (!print_if_unique(iter->input1)) 
						ss << *iter->input1;
					if (iter->input0->is_const() && ((AddrSpace *)iter->input0->offset)->getWordSize() != 1)
						ss << "," << ((AddrSpace *)iter->input0->offset)->getWordSize() << ",*";
					ss << ",[" << iter->output->size << "]";
						
					if (iter->output->is_unique()) 
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_STORE: {
				if (iter->input0 && iter->input1 && iter->output) {
					ss << ",";
					if (!print_if_unique(iter->output)) 
						ss << *iter->output;

					ss << ",";
					if (!print_if_unique(iter->input1)) 
						ss << *iter->input1;
					if (iter->input0->is_const() && ((AddrSpace *)iter->input0->offset)->getWordSize() != 1)
						ss << "," << ((AddrSpace *)iter->input0->offset)->getWordSize() << ",*";
					ss << ",=[" << iter->output->size << "]";
				} else
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
			case CPUI_BRANCH: {
				if (iter->input0) {
					if (iter->input0->is_const())
						throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
					ss << "," << *iter->input0 << "," << sanal.pc_name << ",=";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_CBRANCH: {
				if (iter->input0 && iter->input1) {
					if (!print_if_unique(iter->input1))
						ss << *iter->input1;
					ss << ",?{";

					if (iter->input0->is_const())
						throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
					ss << "," << *iter->input0 << "," << sanal.pc_name << ",=,}";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_PIECE: {
				if (iter->input0 && iter->input1 && iter->output) {
					ss << ",";
					if (!print_if_unique(iter->input0)) 
						ss << *iter->input0;
					ss << "," << (iter->output->size - iter->input0->size) * 8 << ",SWAP,<<";

					ss << ",";
					if (!print_if_unique(iter->input1)) 
						ss << *iter->input1;
					ss << ",|";
					if (iter->output->is_unique()) 
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_SUBPIECE: {
				if (iter->input0 && iter->input1 && iter->output) {
					ss << ",";
					if (!print_if_unique(iter->input0)) 
						ss << *iter->input0;
					if (!iter->input1->is_const())
						throw LowlevelError("sleigh_esil: input1 is not consts in SUBPIECE.");
					ss << "," << iter->input1->number * 8 << ",SWAP,>>";

					if (iter->output->size < iter->input0->size + iter->input1->number)
						ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,SWAP,&";

					if (iter->output->is_unique()) 
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_INT_LESS:
			case CPUI_INT_SLESS:
			case CPUI_INT_LESSEQUAL:
			case CPUI_INT_SLESSEQUAL:
			case CPUI_INT_NOTEQUAL:
			case CPUI_INT_EQUAL: {
				if (iter->input0 && iter->input1 && iter->output) {
					ss << ",";
					if (!print_if_unique(iter->input1)) 
						ss << *iter->input1;
					ss << ",";
					if (!print_if_unique(iter->input0)) 
						ss << *iter->input0;
					ss << ",";
					switch (iter->type) {
						case CPUI_INT_LESS: 
						case CPUI_INT_SLESS: ss << "<"; break;
						case CPUI_INT_LESSEQUAL:
						case CPUI_INT_SLESSEQUAL: ss << "<="; break;
						case CPUI_INT_NOTEQUAL: ss << "!="; break;
						case CPUI_INT_EQUAL: ss << "=="; break;
					}

					if (iter->output->is_unique()) 
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}

			case CPUI_INT_SUB:
			case CPUI_INT_ADD: {
				if (iter->input0 && iter->input1 && iter->output) {
					ss << ",";
					if (!print_if_unique(iter->input1)) 
						ss << *iter->input1;
					ss << ",";
					if (!print_if_unique(iter->input0)) 
						ss << *iter->input0;
					ss << ",";
					switch (iter->type) {
						case CPUI_INT_SUB: ss << "-"; break;
						case CPUI_INT_ADD: ss << "+"; break;
					}
					ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,SWAP,&";

					if (iter->output->is_unique()) 
						push_stack(iter->output);
					else
						ss << "," << *iter->output << ",=";
				} else
					throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
				break;
			}
		}
	}

	if (!esil_stack.empty())
		ss << ",CLEAR";
	esilprintf(anal_op, ss.str()[0] == ',' ?  ss.str().c_str()+1 : ss.str().c_str());
}

static int sleigh_op(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask)
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

	if(pcode_slg.pcodes.empty()) { // NOP case
		anal_op->type = R_ANAL_OP_TYPE_NOP;
		esilprintf(anal_op, "");
		return anal_op->size;
	}

	if (mask & R_ANAL_OP_MASK_ESIL)
		sleigh_esil (a, anal_op, addr, data, len, pcode_slg.pcodes); 

	if(pcode_slg.pcodes.begin()->type == CPUI_CALLOTHER) { // CALLOTHER case, will appear when syscall
		anal_op->type = R_ANAL_OP_TYPE_UNK;
		return anal_op->size;
	}

	SleighInstruction &ins = *sanal.trans.getInstruction(caddr);
	FlowType ftype = ins.getFlowType();
	bool isRefed = false;

	if(ftype != FlowType::FALL_THROUGH) {
		switch(ftype) {
			case FlowType::TERMINATOR:
				//Stack info could be added
				anal_op->type = R_ANAL_OP_TYPE_RET; 
				anal_op->eob = true; 
				break;

			case FlowType::CONDITIONAL_TERMINATOR:
				anal_op->type = R_ANAL_OP_TYPE_CRET; 
				anal_op->fail = ins.getFallThrough().getOffset();
				anal_op->eob = true; 
				break;

			case FlowType::JUMP_TERMINATOR:
				anal_op->eob = true;
			case FlowType::UNCONDITIONAL_JUMP:
				anal_op->type = R_ANAL_OP_TYPE_JMP; 
				anal_op->jump = ins.getFlows().begin()->getOffset();
				break;

			case FlowType::COMPUTED_JUMP: {
				char *reg = getIndirectReg(ins, isRefed);
				if(reg) {
					if (isRefed) {
						anal_op->type = R_ANAL_OP_TYPE_MJMP;
						anal_op->ireg = reg;
					} else {
						anal_op->type = R_ANAL_OP_TYPE_IRJMP;
						anal_op->reg = reg;
					}
				} else 
					anal_op->type = R_ANAL_OP_TYPE_IJMP;
				break;
			}

			case FlowType::CONDITIONAL_COMPUTED_JUMP: {
				char *reg = getIndirectReg(ins, isRefed);
				if(reg) {
					if (isRefed) {
						anal_op->type = R_ANAL_OP_TYPE_MCJMP;
						anal_op->ireg = reg;
					} else {
						anal_op->type = R_ANAL_OP_TYPE_RCJMP;
						anal_op->reg = reg;
					}
				} else 
					anal_op->type = R_ANAL_OP_TYPE_UCJMP;
				anal_op->fail = ins.getFallThrough().getOffset();
				break;
			}

			case FlowType::CONDITIONAL_JUMP:
				anal_op->type = R_ANAL_OP_TYPE_CJMP;
				anal_op->jump = ins.getFlows().begin()->getOffset();
				anal_op->fail = ins.getFallThrough().getOffset();
				break;

			case FlowType::CALL_TERMINATOR:
				anal_op->eob = true;
			case FlowType::UNCONDITIONAL_CALL:
				anal_op->type = R_ANAL_OP_TYPE_CALL;
				anal_op->jump = ins.getFlows().begin()->getOffset();
				anal_op->fail = ins.getFallThrough().getOffset();
				break;

			case FlowType::CONDITIONAL_COMPUTED_CALL: {
				char *reg = getIndirectReg(ins, isRefed);
				if(reg)
					if (isRefed)
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

			case FlowType::COMPUTED_CALL_TERMINATOR: 
				anal_op->eob = true;
			case FlowType::COMPUTED_CALL: {
				char *reg = getIndirectReg(ins, isRefed);
				if(reg) {
					if (isRefed) {
						anal_op->type = R_ANAL_OP_TYPE_IRCALL;
						anal_op->ireg = reg;
					} else {
						anal_op->type = R_ANAL_OP_TYPE_IRCALL;
						anal_op->reg = reg;
					}
				} else 
					anal_op->type = R_ANAL_OP_TYPE_ICALL;
				anal_op->fail = ins.getFallThrough().getOffset();
				break;
			}

			default:
				throw LowlevelError("Unexpected FlowType occured in sleigh_op.");
		}
	} else {

		anal_type(anal_op, pcode_slg, assem); // Label each instruction based on a series of P-codes.

		// anal_op info extraction here!!!

	}

	return anal_op->size;
}

static char *get_reg_profile(RAnal *anal)
{
	// TODO: parse call and return reg usage from compiler spec.
	// TODO: apply attribute get from processor spec(hidden, ...).
	if(!strcmp(anal->cpu, "x86"))
		return nullptr;

	/*
	 * By 2020-05-24, there are 17 kinds of group of registers in SLEIGH.
	 * I map them to r_reg.h's RRegisterType:
	 * R_REG_TYPE_XMM:
	 * R_REG_TYPE_SEG:
	 * R_REG_TYPE_DRX: DEBUG
	 * R_REG_TYPE_FPU: ST FPU
	 * R_REG_TYPE_MMX: MMX
	 * R_REG_TYPE_YMM: AVX
	 * R_REG_TYPE_FLG: FLAGS Flags
	 * R_REG_TYPE_GPR: PC Cx DCR STATUS SVE CONTROL SPR SPR_UNNAMED Alt NEON
	 */
	const char*   r_reg_type_arr[] = {"PC",  "Cx",  "DCR", "STATUS", "SVE", "CONTROL", "SPR", "SPR_UNNAMED", "Alt", "NEON", \
									"FLAGS", "Flags", \
									"AVX", \
									"MMX", \
									"ST", "FPU", \
									"DEBUG", \
									nullptr};
	const char* r_reg_string_arr[] = {"gpr", "gpr", "gpr", "gpr",    "gpr", "gpr",     "gpr", "gpr",         "gpr", "gpr",  \
									"flg",   "flg",   \
									"ymm", \
									"mmx", \
									"fpu", "fpu", \
									"drx", \
									nullptr};

	sanal.init(anal);

	auto reg_list = sanal.getRegs();
	std::stringstream buf;

	if(!sanal.pc_name.empty())
		buf << "=PC\t" << sanal.pc_name << '\n';
	if(!sanal.sp_name.empty())
		buf << "=SP\t" << sanal.sp_name << '\n';

	for(auto p = reg_list.begin(); p != reg_list.end(); p++)
	{
		const std::string &group = sanal.reg_group[p->name];
		if(group.empty())
		{
			buf << "gpr\t" << p->name << "\t." << p->size * 8 << "\t" << p->offset << "\t" << "0\n";
			continue;
		}

		for(size_t i = 0; ; i++)
		{
			if(!r_reg_type_arr[i])
			{
				fprintf(stderr, "anal_ghidra.cpp:get_reg_profile() -> Get unexpected Register group(%s) from SLEIGH, abort.", group.c_str());
				return nullptr;
			}

			if(group == r_reg_type_arr[i])
			{
				buf << r_reg_string_arr[i] << '\t';
				break;
			}
		}

		buf << p->name << "\t." << p->size * 8 << "\t" << p->offset << "\t" << "0\n";
	}
	const std::string &res = buf.str();
	//fprintf(stderr, res.c_str());
	return strdup(res.c_str());
}

static bool sleigh_consts_pick (RAnalEsil *esil) {
	if (!esil || !esil->stack)
		return false;

	char *idx = r_anal_esil_pop (esil);
	ut64 i;
	int ret = false;

	if (R_ANAL_ESIL_PARM_REG == r_anal_esil_get_parm_type (esil, idx)) {
		// ERR ("sleigh_consts_pick: argument is consts only");
		goto end;
	}
	if (!idx || !r_anal_esil_get_parm (esil, idx, &i)) {
		// ERR ("esil_pick: invalid index number");
		goto end;
	}
	if (esil->stackptr < i) {
		// ERR ("esil_pick: index out of stack bounds");
		goto end;
	}
	if (!esil->stack[esil->stackptr-i]) {
		// ERR ("esil_pick: undefined element");
		goto end;
	}
	if (!r_anal_esil_push (esil, esil->stack[esil->stackptr-i])) {
		// ERR ("ESIL stack is full");
		esil->trap = 1;
		esil->trap_code = 1;
		goto end;
	}
	ret = true;
end:
	free (idx);
	return ret;
}

static int esil_sleigh_init (RAnalEsil *esil) {
	if (!esil) {
		return false;
	}

	// Only consts-only version PICK will meet my demand
	r_anal_esil_set_op (esil, "PICK", sleigh_consts_pick, 1, 0, R_ANAL_ESIL_OP_TYPE_CUSTOM);		//better meta info plz

	return true;
}

static int esil_sleigh_fini (RAnalEsil *esil) {
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
