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
        RIO *io;

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

        ~AssemblySlg() { if (str) free (str); }
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
        int alignment;

        RConfig *get_config(RAsm *a);
        std::string get_sleigh_home(RConfig *cfg);
        void collect_specfiles(void);
        void scan_sleigh(const string &rootpath);
        void resolve_arch(const string &archid);
        void build_specfile(DocumentStorage &store);
        void parse_proc_config(DocumentStorage &store);
        void loadLanguageDescription(const string &specfile);
        void parse_alignment(DocumentStorage &doc);

    public:
        SleighAsm() : loader(nullptr), trans(nullptr, nullptr) {}
        void init(RAsm *a);
        int disassemble(RAsmOp *op, unsigned long long offset);
};

#endif //R2GHIDRA_SLEIGHASM_H