/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHASM_H
#define R2GHIDRA_SLEIGHASM_H

#include <string>
#include <vector>
#include <r_core.h>
#include <unordered_map>
#include "architecture.hh"
#include "sleigh_arch.hh"

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

class PcodeSlg : public PcodeEmit
{
	private:
		Sleigh *base_ptr;

		void print_vardata(ostream &s, VarnodeData &data)
		{
			/*
			s << '(' << data.space->getName() << ',';
			data.space->printOffset(s,data.offset);
			s << ',' << dec << data.size << ')';
			*/
			s << base_ptr->getRegisterName(data.space, data.offset, data.size);
		}

	public:
		std::vector<char *> pcodes;

		PcodeSlg(Sleigh *ptr): base_ptr(ptr) {}

		void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override
		{
			std::stringstream ss;
			if(outvar)
			{
				print_vardata(ss,*outvar);
				ss << " = ";
			}
			ss << get_opname(opc);
			// Possibly check for a code reference or a space reference
			for(int4 i=0; i<isize; ++i)
			{
				ss << ' ';
				print_vardata(ss, vars[i]);
			}
			pcodes.push_back(r_str_new(ss.str().c_str()));
		}

		~PcodeSlg()
		{
			while(!pcodes.empty())
			{
				free(pcodes.back());
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

class SleighAsm
{
    private:
		AsmLoadImage loader;
		Sleigh trans;
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
		int alignment = 1;
		std::string pc_name;
		std::string sp_name;
		std::unordered_map<std::string, std::string> reg_group;
		SleighAsm() : loader(nullptr), trans(nullptr, nullptr) {}
		void init(RAsm *a);
		void init(RAnal *a);
		int disassemble(RAsmOp *op, unsigned long long offset);
		int genOpcode(RAnalOp *op, unsigned long long offset);
		std::vector<R2Reg> getRegs(void);
};

#endif //R2GHIDRA_SLEIGHASM_H