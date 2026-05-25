// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-FileCopyrightText: 2020 Nirmal Manoj <nimmumanoj@gmail.com>
// SPDX-FileCopyrightText: 2019 Vasil Sarafov <vasil.sarafov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinArchitecture.h"
#include "CodeXMLParse.h"
#include "ArchMap.h"
#include "PrettyXmlEncode.h"
#include "PcodeFixupPreprocessor.h"
#include "rz_ghidra.h"
#include "rz_ghidra_internal.h"

// Windows clash
#ifdef restrict
#undef restrict
#endif

#include <libdecomp.hh>
#include <printc.hh>

#include <rz_core.h>

#include <vector>
#include <mutex>

using namespace ghidra;

#define CMD_PREFIX "pdg"
#define CFG_PREFIX "ghidra"

class ConfigBase
{
	private:
		static std::vector<ConfigBase *> vars_all;

	protected:
		const std::string name;
		const std::string desc;

		virtual ~ConfigBase() {};
		ConfigBase(std::string var, const char* desc) : name(CFG_PREFIX "." + var), desc(desc) { vars_all.push_back(this); };

	public:
		const char *GetName() const	{ return name.c_str(); }
		const char *GetDesc() const	{ return desc.c_str(); }

		virtual void Add(RzConfig *cfg) = 0;

		static const std::vector<ConfigBase *> &GetAll()	{ return vars_all; }
};

std::vector<ConfigBase *> ConfigBase::vars_all;

class ConfigBool : ConfigBase
{
	private:
		bool defval;

	public:
		ConfigBool(std::string var, const bool defval, const char *desc)
			: ConfigBase(var, desc), defval(defval) {}

		bool Get(RzConfig *cfg) const		{ return rz_config_get_bool(cfg, name.c_str()); };
		void Set(RzConfig *cfg, bool value)	{ rz_config_set_bool(cfg, name.c_str(), value); };
		void Add(RzConfig *cfg)				{ rz_config_add_bool(cfg, name.c_str(), desc.c_str(), defval); };
};

class ConfigInt : ConfigBase
{
	private:
		ut64 defval;

	public:
		ConfigInt(std::string var, const ut64 defval, const char *desc)
			: ConfigBase(var, desc), defval(defval) {}

		ut64 Get(RzConfig *cfg) const		{ return rz_config_get_integer(cfg, name.c_str()); };
		void Set(RzConfig *cfg, ut64 value)	{ rz_config_set_integer(cfg, name.c_str(), value); };
		void Add(RzConfig *cfg)				{ rz_config_add_integer(cfg, name.c_str(), desc.c_str(), defval); };
};

class ConfigStr : ConfigBase
{
	private:
		std::string defval;

	public:
		ConfigStr(std::string var, const std::string defval, const char *desc)
			: ConfigBase(var, desc), defval(defval) {}

		std::string Get(RzConfig *cfg) const		{ return rz_config_get_string(cfg, name.c_str()); };
		void Set(RzConfig *cfg, std::string value)	{ rz_config_set_string(cfg, name.c_str(), value.c_str()); };
		void Add(RzConfig *cfg)						{ rz_config_add_string(cfg, name.c_str(), desc.c_str(), defval.c_str()); };
};

class ConfigBind : public ConfigBase
{
	private:
		RzConfigBindGet get;
		RzConfigBindSet set;
		RzConfigBindOpts opts;
		std::string bind_value;

	public:
		ConfigBind(std::string var, const char *desc, RzConfigBindGet get, RzConfigBindSet set, RzConfigBindOpts opts = nullptr)
			: ConfigBase(var, desc), get(get), set(set), opts(opts) {}

		const char* Get(RzConfig *cfg) const		{ return bind_value.c_str(); };
		void Set(RzConfig *cfg, const char* value)	{
			if (set(NULL, value)) {
				bind_value = value;
			}
		};
		void Add(RzConfig *cfg)						{
			rz_config_add_string_bind(cfg, name.c_str(), desc.c_str(), get, set, opts, static_cast<void *>(this));
		};
};

static std::recursive_mutex decompiler_mutex;
static int lib_init_refcount = 0; // protected by decompiler_mutex, refcounts rz_ghidra_lib_init initialization

static bool SleighHomeConfigSet(void */* user */, const void *pvalue) {
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	auto value = reinterpret_cast<const char *>(pvalue);
	SleighArchitecture::shutdown();
	SleighArchitecture::specpaths = FileManage();
	if(value && *value)
		SleighArchitecture::scanForSleighDirectories(value);
	return true;
}

static bool SleighHomeConfigGet(void *user, void *pvalue) {
	auto cfgbind = reinterpret_cast<ConfigBind *>(user);
	auto value = reinterpret_cast<const char **>(pvalue);
	*value = cfgbind->Get(NULL);
	return true;
}

static ConfigBind cfg_var_sleighhome   ("sleighhome",            "SLEIGHHOME", SleighHomeConfigGet, SleighHomeConfigSet);
static ConfigStr  cfg_var_sleighid     ("lang",        "",       "Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)");
static ConfigBool cfg_var_cmt_cpp      ("cmt.cpp",     true,     "C++ comment style");
static ConfigInt  cfg_var_cmt_indent   ("cmt.indent",  4,        "Comment indent");
static ConfigBool cfg_var_nl_brace     ("nl.brace",    false,    "Newline before opening '{'");
static ConfigBool cfg_var_nl_else      ("nl.else",     false,    "Newline before else");
static ConfigInt  cfg_var_indent       ("indent",      4,        "Indent increment");
static ConfigInt  cfg_var_linelen      ("linelen",     120,      "Max line length");
static ConfigInt  cfg_var_maximplref   ("maximplref",  2,        "Maximum number of references to an expression before showing an explicit variable.");
static ConfigBool cfg_var_rawptr       ("rawptr",      true,     "Show unknown globals as raw addresses instead of variables");
static ConfigBool cfg_var_ropropagate  ("ropropagate", true,     "Propagate read-only memory locations as constants");
static ConfigBool cfg_var_verbose      ("verbose",     true,     "Show verbose warning messages while decompiling");

class DecompilerLock
{
	public:
		DecompilerLock()
		{
			if(!decompiler_mutex.try_lock())
			{
				void *bed = rz_cons_sleep_begin();
				decompiler_mutex.lock();
				rz_cons_sleep_end(bed);
			}
		}

		~DecompilerLock()
		{
			decompiler_mutex.unlock();
		}
};

enum class DecompileMode { DEFAULT, XML, DEBUG_XML, OFFSET, STATEMENTS, JSON };

//#define DEBUG_EXCEPTIONS

static void ApplyPrintCConfig(RzConfig *cfg, PrintC *print_c)
{
	if(!print_c)
		return;

	if(cfg_var_cmt_cpp.Get(cfg))
		print_c->setCPlusPlusStyleComments();
	else
		print_c->setCStyleComments();

	print_c->setSpaceAfterComma(true);

	print_c->setNewlineBeforeOpeningBrace(cfg_var_nl_brace.Get(cfg));
	print_c->setNewlineBeforeElse(cfg_var_nl_else.Get(cfg));
	print_c->setNewlineAfterPrototype(false);
	print_c->setIndentIncrement(cfg_var_indent.Get(cfg));
	print_c->setLineCommentIndent(cfg_var_cmt_indent.Get(cfg));
	print_c->setMaxLineSize(cfg_var_linelen.Get(cfg));
}

static void Decompile(RzCore *core, ut64 addr, DecompileMode mode, std::stringstream &out_stream, RzAnnotatedCode **out_code)
{
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	if(!function)
		throw LowlevelError("No function at this offset");
	RizinArchitecture arch(core, cfg_var_sleighid.Get(core->config));
	DocumentStorage store;
	arch.max_implied_ref = cfg_var_maximplref.Get(core->config);
	arch.readonlypropagate = cfg_var_ropropagate.Get(core->config);
	arch.setRawPtr(cfg_var_rawptr.Get(core->config));
	arch.init(store);
	Funcdata *func = arch.symboltab->getGlobalScope()->findFunction(Address(arch.getDefaultCodeSpace(), function->addr));
	arch.print->setOutputStream(&out_stream);
	arch.setPrintLanguage("rizin-c-language");
	ApplyPrintCConfig(core->config, dynamic_cast<PrintC *>(arch.print));
	if(!func)
		throw LowlevelError("No function in Scope");

	// Other archs are not tested
	if (strcmp(rz_analysis_get_arch_target(core->analysis)->arch, "x86") == 0)
		// Must be called after arch.init(), but before decompiling the function
		PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(function, func, core, arch);

	arch.getCore()->sleepBegin();
	auto action = arch.allacts.getCurrent();
	int res;
#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		action->reset(*func);
		res = action->perform(*func);
#ifndef DEBUG_EXCEPTIONS
	}
	catch(const LowlevelError &error)
	{
		arch.getCore()->sleepEndForce();
		throw error;
	}
#endif
	arch.getCore()->sleepEnd();
	if (res<0)
		eprintf("break\n");
	/*else
	{
		eprintf("Decompilation complete\n");
		if(res==0)
			eprintf("(no change)\n");
	}*/
	if(cfg_var_verbose.Get(core->config))
	{
		for(const auto &warning : arch.getWarnings())
			func->warningHeader("[rz-ghidra] " + warning);
	}
	switch (mode)
	{
		case DecompileMode::XML:
		case DecompileMode::DEFAULT:
		case DecompileMode::JSON:
		case DecompileMode::OFFSET:
		case DecompileMode::STATEMENTS:
			arch.print->setMarkup(true);
			break;
		default:
			break;
	}
	if(mode == DecompileMode::XML)
	{
		out_stream << "<result><function>";
		PrettyXmlEncode enc(out_stream);
		func->encode(enc, 0, true);
		out_stream << "</function><code>";
	}
	switch(mode)
	{
		case DecompileMode::XML:
		case DecompileMode::DEFAULT:
		case DecompileMode::JSON:
		case DecompileMode::OFFSET:
		case DecompileMode::STATEMENTS:
			arch.print->docFunction(func);
			if(mode != DecompileMode::XML)
			{
				*out_code = ParseCodeXML(func, out_stream.str().c_str());
				if (!*out_code)
					throw LowlevelError("Failed to parse XML code from Decompiler");
			}
			break;
		case DecompileMode::DEBUG_XML: {
			PrettyXmlEncode enc(out_stream);
			arch.encode(enc);
			break;
		}
		default:
			break;
	}
}

RZ_API RzAnnotatedCode *rz_ghidra_decompile_annotated_code(RzCore *core, ut64 addr)
{
	DecompilerLock lock;
	RzAnnotatedCode *code = nullptr;
#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		std::stringstream out_stream;
		Decompile(core, addr, DecompileMode::DEFAULT, out_stream, &code);
		return code;
#ifndef DEBUG_EXCEPTIONS
	}
	catch(const LowlevelError &error)
	{
		std::string s = "Ghidra Decompiler Error: " + error.explain;
		char *err = strdup (s.c_str());
 		code = rz_annotated_code_new(err);
		// Push an annotation with: range = full string, type = error
		// For this, we have to modify RzAnnotatedCode to have one more type; for errors
		return code;
	}
#endif
}

static void DecompileCmd(RzCore *core, DecompileMode mode)
{
	DecompilerLock lock;

#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		RzAnnotatedCode *code = nullptr;
		std::stringstream out_stream;
		Decompile(core, core->offset, mode, out_stream, &code);
		switch(mode)
		{
			case DecompileMode::OFFSET:
			{
				RzVector *offsets = rz_annotated_code_line_offsets(code);
				rz_core_annotated_code_print(code, offsets);
				rz_vector_free(offsets);
			}
			break;
			case DecompileMode::DEFAULT:
				rz_core_annotated_code_print(code, nullptr);
				break;
			case DecompileMode::STATEMENTS:
				rz_core_annotated_code_print_comment_cmds(code);
				break;
			case DecompileMode::JSON:
				rz_core_annotated_code_print_json(code);
				break;
			case DecompileMode::XML:
				out_stream << "</code></result>";
				// fallthrough
			default:
				rz_cons_printf("%s\n", out_stream.str().c_str());
				break;
		}
		rz_annotated_code_free(code);
#ifndef DEBUG_EXCEPTIONS
	}
	catch(const LowlevelError &error)
	{
		std::string s = "Ghidra Decompiler Error: " + error.explain;
		if(mode == DecompileMode::JSON)
		{
			PJ *pj = pj_new ();
			if(!pj)
				return;
			pj_o(pj);
			pj_k(pj, "errors");
			pj_a(pj);
			pj_s(pj, s.c_str());
			pj_end(pj);
			pj_end(pj);
			rz_cons_printf ("%s\n", pj_string (pj));
			pj_free(pj);
		}
		else
			eprintf("%s\n", s.c_str());
	}
#endif
}


// see sleighexample.cc
class AssemblyRaw : public AssemblyEmit
{
	public:
		void dump(const Address &addr, const string &mnem, const string &body) override
		{
			std::stringstream ss;
			addr.printRaw(ss);
			ss << ": " << mnem << ' ' << body;
			rz_cons_printf("%s\n", ss.str().c_str());
		}
};

class PcodeRawOut : public PcodeEmit
{
	private:
		const Translate *trans = nullptr;

		void print_vardata(ostream &s, VarnodeData &data)
		{
			AddrSpace *space = data.space;
			if(space->getName() == "register" || space->getName() == "mem")
			    s << space->getTrans()->getRegisterName(data.space, data.offset, data.size);
		    else if(space->getName() == "ram")
		    {
			    if(data.size == 1)
				    s << "byte_ptr(";
			    if(data.size == 2)
				    s << "word_ptr(";
			    if(data.size == 4)
				    s << "dword_ptr(";
			    if(data.size == 8)
				    s << "qword_ptr(";
			    space->printRaw(s, data.offset);
			    s << ')';
		    }
		    else if(space->getName() == "const")
			    static_cast<ConstantSpace *>(space)->printRaw(s, data.offset);
		    else if(space->getName() == "unique")
		    {
			    s << '(' << data.space->getName() << ',';
			    data.space->printOffset(s, data.offset);
			    s << ',' << dec << data.size << ')';
		    }
		    else if(space->getName() == "DATA")
			{
				s << '(' << data.space->getName() << ',';
				data.space->printOffset(s,data.offset);
				s << ',' << dec << data.size << ')';
			}
			else
			{
			    s << '(' << data.space->getName() << ',';
			    data.space->printOffset(s, data.offset);
			    s << ',' << dec << data.size << ')';
		    }
	    }

	public:
	    PcodeRawOut(const Translate *t): trans(t) {}

	    void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars,
	              int4 isize) override
	    {
		    std::stringstream ss;
		    if(opc == CPUI_STORE && isize == 3)
		    {
			    print_vardata(ss, vars[2]);
			    ss << " = ";
			    isize = 2;
		    }
		    if(outvar)
		    {
			    print_vardata(ss,*outvar);
				ss << " = ";
		    }
		    ss << get_opname(opc);
			// Possibly check for a code reference or a space reference
			ss << ' ';
			// For indirect case in SleighBuilder::dump(OpTpl *op)'s "vn->isDynamic(*walker)" branch.
			if (isize > 1 && vars[0].size == sizeof(AddrSpace *) && vars[0].space->getName() == "const"
				&& (vars[0].offset >> 24) == ((uintb)vars[1].space >> 24) && trans == ((AddrSpace*)vars[0].offset)->getTrans())
			{
				ss << ((AddrSpace*)vars[0].offset)->getName();
			    ss << '[';
			    print_vardata(ss, vars[1]);
			    ss << ']';
			    for(int4 i = 2; i < isize; ++i)
			    {
				    ss << ", ";
				    print_vardata(ss, vars[i]);
			    }
		    }
		    else
		    {
			    print_vardata(ss, vars[0]);
			    for(int4 i = 1; i < isize; ++i)
			    {
				    ss << ", ";
					print_vardata(ss, vars[i]);
			    }
		    }
			rz_cons_printf("    %s\n", ss.str().c_str());
	    }
};

static void Disassemble(RzCore *core, ut64 ops)
{
	if(!ops)
		ops = 10; // random default value

	RizinArchitecture arch(core, cfg_var_sleighid.Get(core->config));
	DocumentStorage store;
	arch.init(store);

	const Translate *trans = arch.translate;
	PcodeRawOut emit(arch.translate);
	AssemblyRaw assememit;
	Address addr(trans->getDefaultCodeSpace(), core->offset);
	for(ut64 i=0; i<ops; i++)
	{
		try
		{
			trans->printAssembly(assememit, addr);
			auto length = trans->oneInstruction(emit, addr);
			addr = addr + length;
		}
		catch(const BadDataError &error)
		{
			std::stringstream ss;
			addr.printRaw(ss);
			rz_cons_printf("%s: invalid\n", ss.str().c_str());
			addr = addr + trans->getAlignment();
		}
	}
}

static void ListSleighLangs()
{
	DecompilerLock lock;

	SleighArchitecture::collectSpecFiles(std::cerr);
	auto langs = SleighArchitecture::getLanguageDescriptions();
	if(langs.empty())
	{
		rz_cons_printf("No languages available, make sure %s is set correctly!\n", cfg_var_sleighhome.GetName());
		return;
	}

	std::vector<std::string> ids;
	std::transform(langs.begin(), langs.end(), std::back_inserter(ids), [](const LanguageDescription &lang) { return lang.getId(); });
	std::sort(ids.begin(), ids.end());
	std::for_each(ids.begin(), ids.end(), [](const std::string &id) {
		rz_cons_printf("%s\n", id.c_str());
	});
}

static void PrintAutoSleighLang(RzCore *core)
{
	DecompilerLock lock;
	try
	{
		auto id = SleighIdFromCore(core);
		rz_cons_printf("%s\n", id.c_str());
	}
	catch(LowlevelError &e)
	{
		eprintf("%s\n", e.explain.c_str());
	}
}

static void EnablePlugin(RzCore *core)
{
	auto id = SleighIdFromCore(core);
	rz_config_set(core->config, "ghidra.lang", id.c_str());
	rz_config_set(core->config, "asm.arch", "ghidra");
	rz_config_set(core->config, "asm.cpu", id.c_str());
}

static void SetInitialSleighHome(RzConfig *cfg)
{
	// user-set, for example from .rizinrc
	std::string user_set = cfg_var_sleighhome.Get(cfg);
	if(!user_set.empty())
		return;

	// SLEIGHHOME env
	const char *sleighhomepath = getenv("SLEIGHHOME");
	if(sleighhomepath && *sleighhomepath)
	{
		cfg_var_sleighhome.Set(cfg, sleighhomepath);
		return;
	}

#ifdef RZ_GHIDRA_SLEIGHHOME_DEFAULT
	if(rz_file_is_directory(RZ_GHIDRA_SLEIGHHOME_DEFAULT))
	{
		cfg_var_sleighhome.Set(cfg, RZ_GHIDRA_SLEIGHHOME_DEFAULT);
		return;
	}
#endif

	// rz-pm-installed ghidra
	char *homepath = rz_str_home(".local/share/rizin/rz-pm/git/ghidra");
	if(homepath && rz_file_is_directory(homepath))
	{
		cfg_var_sleighhome.Set(cfg, homepath);
	}
	rz_mem_free (homepath);
}

#define with(T, ...) ([]{ T ${}; __VA_ARGS__; return $; }())

static const RzCmdDescArg args_none[] = {{}};

static RzCmdDescDetailEntry root_details_env[] = {
	with(RzCmdDescDetailEntry,
		$.text = "$SLEIGHHOME";
		$.comment = "Path to ghidra build root directory"
	),
	{}
};

static RzCmdDescDetail root_details[] = {
	with(RzCmdDescDetail,
		$.name = "Environment",
		$.entries = root_details_env
	),
	{}
};

static const RzCmdDescHelp root_help = with(RzCmdDescHelp,
	$.summary = "Native Ghidra decompiler and Sleigh Disassembler plugin";
	$.args = args_none;
	$.details = root_details
);

static const RzCmdDescHelp pdg_help = with(RzCmdDescHelp,
	$.summary = "Decompile current function with the Ghidra decompiler";
	$.args = args_none
);

static RzCmdStatus pdg_handler(RzCore *core, int argc, const char **argv) {
	DecompileCmd(core, DecompileMode::DEFAULT);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdgd_help = with(RzCmdDescHelp,
	$.summary = "Dump the debug XML Dump";
	$.args = args_none
);

static RzCmdStatus pdgd_handler(RzCore *core, int argc, const char **argv) {
	DecompileCmd(core, DecompileMode::DEBUG_XML);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdgx_help = with(RzCmdDescHelp,
	$.summary = "Dump the XML of the current decompiled function";
	$.args = args_none
);

static RzCmdStatus pdgx_handler(RzCore *core, int argc, const char **argv) {
	DecompileCmd(core, DecompileMode::XML);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdgj_help = with(RzCmdDescHelp,
	$.summary = "Dump the current decompiled function as JSON";
	$.args = args_none
);

static RzCmdStatus pdgj_handler(RzCore *core, int argc, const char **argv) {
	DecompileCmd(core, DecompileMode::JSON);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdgo_help = with(RzCmdDescHelp,
	$.summary = "Decompile current function side by side with offsets";
	$.args = args_none
);

static RzCmdStatus pdgo_handler(RzCore *core, int argc, const char **argv) {
	DecompileCmd(core, DecompileMode::OFFSET);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdgs_help = with(RzCmdDescHelp,
	$.summary = "Display loaded Sleigh Languages";
	$.args = args_none
);

static RzCmdStatus pdgs_handler(RzCore *core, int argc, const char **argv) {
	ListSleighLangs();
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdgss_help = with(RzCmdDescHelp,
	$.summary = "Display automatically matched Sleigh Language ID";
	$.args = args_none
);

static RzCmdStatus pdgss_handler(RzCore *core, int argc, const char **argv) {
	PrintAutoSleighLang(core);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescArg pdgsd_args[] = {
	with(RzCmdDescArg,
		$.name = "N";
		$.optional = true;
		$.type = RZ_CMD_ARG_TYPE_NUM;
	),
	{},
};

static const RzCmdDescHelp pdgsd_help = with(RzCmdDescHelp,
	$.summary = "Disassemble N instructions with Sleigh and print pcode";
	$.args = pdgsd_args;
);

static RzCmdStatus pdgsd_handler(RzCore *core, int argc, const char **argv) {
	ut64 ops = argc > 1 ? (ut64)strtoull(argv[1], nullptr, 0) : 0;
	Disassemble(core, ops);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdga_help = with(RzCmdDescHelp,
	$.summary = "Switch to RzAsm and RzAnalysis plugins driven by SLEIGH from Ghidra";
	$.args = args_none
);

static RzCmdStatus pdga_handler(RzCore *core, int argc, const char **argv) {
	EnablePlugin(core);
	return RZ_CMD_STATUS_OK;
}

static const RzCmdDescHelp pdgstar_help = with(RzCmdDescHelp,
	$.summary = "Decompiled code is returned to rizin as comment";
	$.args = args_none
);

static RzCmdStatus pdgstar_handler(RzCore *core, int argc, const char **argv) {
	DecompileCmd(core, DecompileMode::STATEMENTS);
	return RZ_CMD_STATUS_OK;
}

void rz_ghidra_lib_init(void)
{
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	lib_init_refcount++;
	startDecompilerLibrary(nullptr);
}

void rz_ghidra_lib_fini(void)
{
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	lib_init_refcount--;
	if(lib_init_refcount < 0)
		return;
	if(lib_init_refcount == 0)
		shutdownDecompilerLibrary();
}

static bool rz_ghidra_init(RzCore *core)
{
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	rz_ghidra_lib_init();

	RzConfig *cfg = core->config;
	for(auto var : ConfigBase::GetAll())
	{
		var->Add(cfg);
	}

	auto rzcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_desc_group_new(rzcmd, rz_cmd_get_desc(rzcmd, "pd"), "pdg", pdg_handler, &pdg_help, &root_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdgd", pdgd_handler, &pdgd_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdgx", pdgx_handler, &pdgx_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdgj", pdgj_handler, &pdgj_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdgo", pdgo_handler, &pdgo_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdgs", pdgs_handler, &pdgs_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdgss", pdgss_handler, &pdgss_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdgsd", pdgsd_handler, &pdgsd_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdga", pdga_handler, &pdga_help);
	rz_cmd_desc_argv_new(rzcmd, root_cd, "pdg*", pdgstar_handler, &pdgstar_help);
	SetInitialSleighHome(cfg);
	return true;
}

static bool rz_ghidra_fini(RzCore *core)
{
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	rz_ghidra_lib_fini();

	auto rzcmd = core->rcmd;
	RzCmdDesc *pdg_cd = rz_cmd_get_desc(rzcmd, "pdg");
	rz_cmd_desc_remove(rzcmd, pdg_cd);
	return true;
}

RzCorePlugin rz_core_plugin_ghidra = {
	/* .name = */ "ghidra",
	/* .desc = */ "Ghidra integration",
	/* .license = */ "LGPL3",
	/* .author = */ "thestr4ng3r",
	/* .version = */ nullptr,
	/*.init = */ rz_ghidra_init,
	/*.fini = */ rz_ghidra_fini
};

#ifndef CORELIB
extern "C" {
RZ_API RzLibStruct rizin_plugin = {
	/* .type = */ RZ_LIB_TYPE_CORE,
	/* .data = */ &rz_core_plugin_ghidra,
	/* .version = */ RZ_VERSION,
	/* .free = */ nullptr,
};
}
#endif
