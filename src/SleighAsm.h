/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHASM_H
#define R2GHIDRA_SLEIGHASM_H

#include <string>
#include <vector>
#include <r_core.h>
#include <unordered_map>
#include "architecture.hh"
#include "sleigh_arch.hh"
#include "SleighInstruction.h"

class AsmLoadImage : public LoadImage
{
private:
	RIO *io = nullptr;

public:
	AsmLoadImage(RIO *io): LoadImage("radare2_program"), io(io) {}
	virtual void loadFill(uint1 *ptr, int4 size, const Address &addr)
	{
		r_io_read_at(io, addr.getOffset(), ptr, size);
	}
	virtual string getArchType(void) const { return "radare2"; }
	virtual void adjustVma(long adjust)
	{
		throw LowlevelError("Cannot adjust radare2 virtual memory");
	}
};

class SleighAsm;
class AssemblySlg : public AssemblyEmit
{
private:
	SleighAsm *sasm = nullptr;

public:
	char *str = nullptr;

	AssemblySlg(SleighAsm *s): sasm(s) {}

	void dump(const Address &addr, const string &mnem, const string &body) override;

	~AssemblySlg()
	{
		if(str)
			r_mem_free(str);
	}
};

struct PcodeOperand
{
	PcodeOperand(uintb offset, uint4 size): type(RAM), offset(offset), size(size) {}
	PcodeOperand(uintb number): type(CONST), number(number), size(0) {}
	PcodeOperand(const std::string &name, uint4 size): type(REGISTER), name(name), size(size) {}
	virtual ~PcodeOperand()
	{
		if(type == REGISTER)
			name.~string();
	}

	union
	{
		std::string name;
		uintb offset;
		uintb number;
	};
	uint4 size;

	enum
	{
		REGISTER,
		RAM,
		CONST,
		UNIQUE
	} type;

	PcodeOperand(const PcodeOperand &rhs)
	{
		type = rhs.type;
		size = rhs.size;

		switch(type)
		{
			case REGISTER: name = rhs.name; break;
			case UNIQUE: /* Same as RAM */
			case RAM: offset = rhs.offset; break;
			case CONST: number = rhs.number; break;
			default: throw LowlevelError("Unexpected type of PcodeOperand found in operator==.");
		}
	}

	bool operator==(const PcodeOperand &rhs) const
	{
		if(type != rhs.type)
			return false;

		switch(type)
		{
			case REGISTER: return name == rhs.name;
			case UNIQUE: /* Same as RAM */
			case RAM: return offset == rhs.offset && size == rhs.size;
			case CONST: return number == rhs.number;
			default: throw LowlevelError("Unexpected type of PcodeOperand found in operator==.");
		}
	}

	bool is_unique() const { return type == UNIQUE; }

	bool is_const() const { return type == CONST; }

	bool is_ram() const { return type == RAM; }

	bool is_reg() const { return type == REGISTER; }
};

ostream &operator<<(ostream &s, const PcodeOperand &arg);

typedef OpCode PcodeOpType;

struct Pcodeop
{
	PcodeOpType type;

	PcodeOperand *output = nullptr;
	PcodeOperand *input0 = nullptr;
	PcodeOperand *input1 = nullptr;
	/* input2 for STORE will use output to save memory space */

	Pcodeop(PcodeOpType opc, PcodeOperand *in0, PcodeOperand *in1, PcodeOperand *out):
	    type(opc), input0(in0), input1(in1), output(out)
	{
	}

	void fini()
	{
		if(output)
			delete output;
		if(input0)
			delete input0;
		if(input1)
			delete input1;
	}
};

ostream &operator<<(ostream &s, const Pcodeop &op);

struct UniquePcodeOperand: public PcodeOperand
{
	const Pcodeop *def = nullptr;
	UniquePcodeOperand(const PcodeOperand *from): PcodeOperand(*from) {}
	~UniquePcodeOperand() = default;
};

class PcodeSlg : public PcodeEmit
{
private:
	SleighAsm *sanal = nullptr;

	PcodeOperand *parse_vardata(VarnodeData &data);

public:
	std::vector<Pcodeop> pcodes;

	PcodeSlg(SleighAsm *s): sanal(s) {}

	void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars,
	          int4 isize) override
	{
		PcodeOperand *out = nullptr, *in0 = nullptr, *in1 = nullptr;

		if(opc == CPUI_CALLOTHER)
			isize = isize > 2? 2: isize;

		switch(isize)
		{
			case 3: out = parse_vardata(vars[2]); // Only for STORE
			case 2: in1 = parse_vardata(vars[1]);
			case 1: in0 = parse_vardata(vars[0]);
			case 0: break;
			default: throw LowlevelError("Unexpexted isize in PcodeSlg::dump()");
		}

		if(outvar)
			out = parse_vardata(*outvar);

		pcodes.push_back(Pcodeop(opc, in0, in1, out));
	}

	~PcodeSlg()
	{
		while(!pcodes.empty())
		{
			pcodes.back().fini();
			pcodes.pop_back();
		}
	}
};

struct R2Reg
{
	std::string name;
	ut64 size;
	ut64 offset;
};

class R2Sleigh;

class SleighAsm
{
private:
	AsmLoadImage loader;
	ContextInternal context;
	DocumentStorage docstorage;
	FileManage specpaths;
	std::vector<LanguageDescription> description;
	int languageindex;

	void initInner(RIO *io, const char *cpu);
	void initRegMapping(void);
	std::string getSleighHome(RConfig *cfg);
	void collectSpecfiles(void);
	void scanSleigh(const string &rootpath);
	void resolveArch(const string &archid);
	void buildSpecfile(DocumentStorage &store);
	void parseProcConfig(DocumentStorage &store);
	void parseCompConfig(DocumentStorage &store);
	void loadLanguageDescription(const string &specfile);

public:
	R2Sleigh trans;
	std::string sleigh_id;
	int alignment = 1;
	std::string pc_name;
	std::string sp_name;
	std::vector<std::string> arg_names; // default ABI's function args
	std::vector<std::string> ret_names; // default ABI's function retvals
	std::unordered_map<std::string, std::string> reg_group;
	// To satisfy radare2's rule: reg name has to be lowercase.
	std::unordered_map<std::string, std::string> reg_mapping;
	SleighAsm(): loader(nullptr), trans(nullptr, nullptr) {}
	void init(const char *sleigh_id, RIO *io, RConfig *cfg);
	int disassemble(RAsmOp *op, unsigned long long offset);
	int genOpcode(PcodeSlg &pcode_slg, Address &addr);
	std::vector<R2Reg> getRegs(void);
	static RConfig *getConfig(RAsm *a);
	static RConfig *getConfig(RAnal *a);
	void check(ut64 offset, const ut8 *buf, int len)
	{ // To refresh cache when file content is modified.
		ParserContext *ctx = trans.getContext(Address(trans.getDefaultCodeSpace(), offset), ParserContext::uninitialized);
		if(ctx->getParserState() > ParserContext::uninitialized)
		{
			ut8 *cached = ctx->getBuffer();
			int i = 0;
			for(; i < len && cached[i] == buf[i]; ++i) {}
			if(i != len)
				ctx->setParserState(ParserContext::uninitialized);
		}
	}
};

#endif // R2GHIDRA_SLEIGHASM_H