/* radare - LGPL - Copyright 2020 - FXTi */

#ifndef R2GHIDRA_SLEIGHASM_H
#define R2GHIDRA_SLEIGHASM_H

#include <string>
#include <vector>
#include <r_core.h>
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
        int alignment = 1;

        RConfig *getConfig(RAsm *a);
        std::string getSleighHome(RConfig *cfg);
        void collectSpecfiles(void);
        void scanSleigh(const string &rootpath);
        void resolveArch(const string &archid);
        void buildSpecfile(DocumentStorage &store);
        void parseProcConfig(DocumentStorage &store);
        void loadLanguageDescription(const string &specfile);
        void parseAlignment(DocumentStorage &doc);

    public:
        SleighAsm() : loader(nullptr), trans(nullptr, nullptr) {}
        void init(RAsm *a);
        int disassemble(RAsmOp *op, unsigned long long offset);
};

#endif //R2GHIDRA_SLEIGHASM_H