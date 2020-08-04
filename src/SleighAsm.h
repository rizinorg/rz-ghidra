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
        AsmLoadImage(RIO *io) : LoadImage("radare2_program"), io(io) {}
        virtual void loadFill(uint1 *ptr,int4 size,const Address &addr)
        {
            r_io_read_at(io, addr.getOffset(), ptr, size);
        }
        virtual string getArchType(void) const { return "radare2"; }
        virtual void adjustVma(long adjust)
        {
            throw LowlevelError("Cannot adjust radare2 virtual memory");
        }
};

class AssemblySlg : public AssemblyEmit
{
	public:
        char *str = nullptr;

		void dump(const Address &addr, const string &mnem, const string &body) override
		{
			str = r_str_newf("%s %s", mnem.c_str(), body.c_str());
		}

        ~AssemblySlg() { if(str) free(str); }
};

struct PcodeOperand
{
	public:
		PcodeOperand(uintb offset, uint4 size): type(RAM), offset(offset), size(size) {}
		PcodeOperand(uintb number): type(CONST), number(number) {}
		PcodeOperand(const std::string &name): type(REGISTER), name(name) {}
		~PcodeOperand() { if(type == REGISTER) name.~string(); }

		union
		{
			std::string name;
			struct
			{
				uintb offset;
				uint4 size;
			};
			uintb number;
		};

		enum {REGISTER, RAM, CONST, UNIQUE} type;

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
};

typedef OpCode PcodeOpType;

struct Pcodeop
{
	PcodeOpType type;

	PcodeOperand *output = nullptr;
	PcodeOperand *input0 = nullptr;
	PcodeOperand *input1 = nullptr;
	/* input2 for STORE will use output to save memory space */

	Pcodeop(PcodeOpType opc, PcodeOperand *in0, PcodeOperand *in1, PcodeOperand *out):
		type(opc), input0(in0), input1(in1), output(out) {}

	void fini()
	{
		if(output) delete output;
		if(input0) delete input0;
		if(input1) delete input1;
	}
};

class PcodeSlg : public PcodeEmit
{
	private:
		PcodeOperand *parse_vardata(VarnodeData &data)
		{
			AddrSpace *space = data.space;
			PcodeOperand *operand = nullptr;
			if(space->getName() == "register")
			{
				operand = new PcodeOperand(space->getTrans()->getRegisterName(data.space, data.offset, data.size));
				operand->type = PcodeOperand::REGISTER;
			}
			else if(space->getName() == "ram")
			{
				operand = new PcodeOperand(data.offset, data.size);
				operand->type = PcodeOperand::RAM;
			}
			else if(space->getName() == "const")
			{
				// space.cc's ConstantSpace::printRaw()
				operand = new PcodeOperand(data.offset);
				operand->type = PcodeOperand::CONST;
			}
			else if(space->getName() == "unique")
			{
				operand = new PcodeOperand(data.offset, data.size);
				operand->type = PcodeOperand::UNIQUE;
			}
			else
			{
				throw LowlevelError("Unsupported AddrSpace type appear.");
			}
			return operand;
		}

	public:
		std::vector<Pcodeop> pcodes;

		void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override
		{
			PcodeOperand *out = nullptr, *in0 = nullptr, *in1 = nullptr;
			if(outvar)
				out = parse_vardata(*outvar);

			switch(isize)
			{
				case 3: out = parse_vardata(vars[2]); // Only for STORE
				case 2: in1 = parse_vardata(vars[1]);
				case 1: in0 = parse_vardata(vars[0]);
				case 0: break;
				default: throw LowlevelError("Unexpexted isize in PcodeSlg::dump()");
			}

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
	size_t size;
	size_t offset;
};

class R2Sleigh;

class SleighAsm
{
    private:
		AsmLoadImage loader;
		ContextInternal context;
		DocumentStorage docstorage;
		std::string sleigh_id;
		FileManage specpaths;
		std::vector<LanguageDescription> description;
		int languageindex;

		RConfig *getConfig(RAsm *a);
		RConfig *getConfig(RAnal *a);
		void initInner(RIO *io, char *cpu);
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
		int alignment = 1;
		std::string pc_name;
		std::string sp_name;
		std::unordered_map<std::string, std::string> reg_group;
		SleighAsm() : loader(nullptr), trans(nullptr, nullptr) {}
		void init(RAsm *a);
		void init(RAnal *a);
		int disassemble(RAsmOp *op, unsigned long long offset);
		int genOpcode(PcodeSlg &pcode_slg, Address &addr);
		std::vector<R2Reg> getRegs(void);
};

#endif //R2GHIDRA_SLEIGHASM_H