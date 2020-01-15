/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2Architecture.h"
#include "CodeXMLParse.h"
#include "ArchMap.h"

// Windows clash
#ifdef restrict
#undef restrict
#endif

#include <libdecomp.hh>
#include <printc.hh>

#include <r_core.h>

#include <vector>
#include <mutex>

#define CMD_PREFIX "pdg"
#define CFG_PREFIX "r2ghidra"

typedef bool (*ConfigVarCb)(void *user, void *data);

struct ConfigVar
{
	private:
		static std::vector<const ConfigVar *> vars_all;

		const std::string name;
		const char * const defval;
		const char * const desc;
		ConfigVarCb callback;

	public:
		ConfigVar(const char *var, const char *defval, const char *desc, ConfigVarCb callback = nullptr)
			: name(std::string(CFG_PREFIX) + "." + var), defval(defval), desc(desc), callback(callback) { vars_all.push_back(this); }

		const char *GetName() const					{ return name.c_str(); }
		const char *GetDefault() const				{ return defval; }
		const char *GetDesc() const					{ return desc; }
		ConfigVarCb GetCallback() const				{ return callback; }

		ut64 GetInt(RConfig *cfg) const				{ return r_config_get_i(cfg, name.c_str()); }
		bool GetBool(RConfig *cfg) const			{ return GetInt(cfg) != 0; }
		std::string GetString(RConfig *cfg) const	{ return r_config_get(cfg, name.c_str()); }

		void Set(RConfig *cfg, const char *s) const	{ r_config_set(cfg, name.c_str(), s); }

		static const std::vector<const ConfigVar *> &GetAll()	{ return vars_all; }
};
std::vector<const ConfigVar *> ConfigVar::vars_all;

bool SleighHomeConfig(void *user, void *data);

static const ConfigVar cfg_var_sleighhome   ("sleighhome",  "",         "SLEIGHHOME", SleighHomeConfig);
static const ConfigVar cfg_var_sleighid     ("lang",        "",         "Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)");
static const ConfigVar cfg_var_cmt_cpp      ("cmt.cpp",     "true",     "C++ comment style");
static const ConfigVar cfg_var_cmt_indent   ("cmt.indent",  "4",        "Comment indent");
static const ConfigVar cfg_var_nl_brace     ("nl.brace",    "false",    "Newline before opening '{'");
static const ConfigVar cfg_var_nl_else      ("nl.else",     "false",    "Newline before else");
static const ConfigVar cfg_var_indent       ("indent",      "4",        "Indent increment");
static const ConfigVar cfg_var_linelen      ("linelen",     "120",      "Max line length");
static const ConfigVar cfg_var_rawptr       ("rawptr",      "true",     "Show unknown globals as raw addresses instead of variables");
static const ConfigVar cfg_var_verbose      ("verbose",      "true",    "Show verbose warning messages while decompiling");



static std::recursive_mutex decompiler_mutex;

class DecompilerLock
{
	public:
		DecompilerLock()
		{
			if(!decompiler_mutex.try_lock())
			{
				void *bed = r_cons_sleep_begin();
				decompiler_mutex.lock();
				r_cons_sleep_end(bed);
			}
		}

		~DecompilerLock()
		{
			decompiler_mutex.unlock();
		}
};

static void PrintUsage(const RCore *const core)
{
	const char* help[] = {
		"Usage: " CMD_PREFIX, "", "# Native Ghidra decompiler plugin",
		CMD_PREFIX, "", "# Decompile current function with the Ghidra decompiler",
		CMD_PREFIX, "d", "# Dump the debug XML Dump",
		CMD_PREFIX, "x", "# Dump the XML of the current decompiled function",
		CMD_PREFIX, "j", "# Dump the current decompiled function as JSON",
		CMD_PREFIX, "o", "# Decompile current function side by side with offsets",
		CMD_PREFIX, "s", "# Display loaded Sleigh Languages",
		CMD_PREFIX, "ss", "# Display automatically matched Sleigh Language ID",
		CMD_PREFIX, "*", "# Decompiled code is returned to r2 as comment",
		"Environment:", "", "",
		"%SLEIGHHOME" , "", "# Path to ghidra build root directory",
		NULL
	};

	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

enum class DecompileMode { DEFAULT, XML, DEBUG_XML, OFFSET, STATEMENTS, JSON };

//#define DEBUG_EXCEPTIONS

static void ApplyPrintCConfig(RConfig *cfg, PrintC *print_c)
{
	if(!print_c)
		return;

	if(cfg_var_cmt_cpp.GetBool(cfg))
		print_c->setCPlusPlusStyleComments();
	else
		print_c->setCStyleComments();

	print_c->setSpaceAfterComma(true);

	print_c->setNewlineBeforeOpeningBrace(cfg_var_nl_brace.GetBool(cfg));
	print_c->setNewlineBeforeElse(cfg_var_nl_else.GetBool(cfg));
	print_c->setNewlineAfterPrototype(false);
	print_c->setIndentIncrement(cfg_var_indent.GetInt(cfg));
	print_c->setLineCommentIndent(cfg_var_cmt_indent.GetInt(cfg));
	print_c->setMaxLineSize(cfg_var_linelen.GetInt(cfg));
}

static void Decompile(RCore *core, DecompileMode mode)
{
	DecompilerLock lock;

#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		RAnalFunction *function = r_anal_get_fcn_in(core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
		if(!function)
			throw LowlevelError("No function at this offset");

		R2Architecture arch(core, cfg_var_sleighid.GetString(core->config));
		DocumentStorage store;
		arch.setRawPtr(cfg_var_rawptr.GetBool(core->config));
		arch.init(store);

		std::stringstream out_stream;
		arch.print->setOutputStream(&out_stream);

		arch.setPrintLanguage("r2-c-language");
		ApplyPrintCConfig(core->config, dynamic_cast<PrintC *>(arch.print));

		Funcdata *func = arch.symboltab->getGlobalScope()->findFunction(Address(arch.getDefaultSpace(), function->addr));
		if(!func)
			throw LowlevelError("No function in Scope");

		arch.sleepBegin();
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
			arch.sleepEndForce();
			throw error;
		}
#endif
		arch.sleepEnd();
		if (res<0)
			eprintf("break\n");
		/*else
		{
			eprintf("Decompilation complete\n");
			if(res==0)
				eprintf("(no change)\n");
		}*/

		if(cfg_var_verbose.GetBool(core->config))
		{
			for(const auto &warning : arch.getWarnings())
				func->warningHeader("[r2ghidra] " + warning);
		}

		switch (mode)
		{
			case DecompileMode::XML:
			case DecompileMode::DEFAULT:
			case DecompileMode::JSON:
			case DecompileMode::OFFSET:
			case DecompileMode::STATEMENTS:
				arch.print->setXML(true);
				break;
			default:
				break;
		}

		if(mode == DecompileMode::XML)
		{
			out_stream << "<result><function>";
			func->saveXml(out_stream, true);
			out_stream << "</function><code>";
		}

		RAnnotatedCode *code = nullptr;
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
					code = ParseCodeXML(func, out_stream.str().c_str());
					if (!code)
						throw LowlevelError("Failed to parse XML code from Decompiler");
				}
				break;
			case DecompileMode::DEBUG_XML:
				arch.saveXml(out_stream);
				break;
			default:
				break;
		}

		switch(mode)
		{
			case DecompileMode::OFFSET:
			{
				RVector *offsets = r_annotated_code_line_offsets(code);
				r_annotated_code_print(code, offsets);
				r_vector_free(offsets);
			}
			break;
			case DecompileMode::DEFAULT:
				r_annotated_code_print(code, nullptr);
				break;
			case DecompileMode::STATEMENTS:
				r_annotated_code_print_comment_cmds(code);
				break;
			case DecompileMode::JSON:
				r_annotated_code_print_json(code);
				break;
			case DecompileMode::XML:
				out_stream << "</code></result>";
				// fallthrough
			default:
				r_cons_printf("%s\n", out_stream.str().c_str());
				break;
		}

		r_annotated_code_free(code);
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
			r_cons_printf ("%s\n", pj_string (pj));
			pj_free(pj);
		}
		else
			eprintf("%s\n", s.c_str());
	}
#endif
}

static void ListSleighLangs()
{
	DecompilerLock lock;

	SleighArchitecture::collectSpecFiles(std::cerr);
	auto langs = SleighArchitecture::getLanguageDescriptions();
	if(langs.empty())
	{
		r_cons_printf("No languages available, make sure %s is set correctly!\n", cfg_var_sleighhome.GetName());
		return;
	}

	for(const auto &lang : langs)
		r_cons_printf("%s\n", lang.getId().c_str());
}

static void PrintAutoSleighLang(RCore *core)
{
	DecompilerLock lock;
	try
	{
		auto id = SleighIdFromCore(core);
		r_cons_printf("%s\n", id.c_str());
	}
	catch(LowlevelError &e)
	{
		eprintf("%s\n", e.explain.c_str());
	}
}

static void _cmd(RCore *core, const char *input)
{
	switch (*input)
	{
		case 'd': // "pdgd"
			Decompile(core, DecompileMode::DEBUG_XML);
			break;
		case '\0': // "pdg"
			Decompile(core, DecompileMode::DEFAULT);
			break;
		case 'x': // "pdgx"
			Decompile(core, DecompileMode::XML);
			break;
		case 'j': // "pdgj"
			Decompile(core, DecompileMode::JSON);
			break;
		case 'o': // "pdgo"
			Decompile(core, DecompileMode::OFFSET);
			break;
		case '*': // "pdg*"
			Decompile(core, DecompileMode::STATEMENTS);
			break;
		case 's': // "pdgs"
			if (input[1] == 's') // "pdgss"
				PrintAutoSleighLang(core);
			else
				ListSleighLangs();
			break;
		default:
			PrintUsage(core);
			break;
	}
}

static int r2ghidra_cmd(void *user, const char *input)
{
	RCore *core = (RCore *) user;
	if (!strncmp (input, CMD_PREFIX, strlen(CMD_PREFIX)))
	{
		_cmd (core, input + 3);
		return true;
	}
	return false;
}

bool SleighHomeConfig(void */* user */, void *data)
{
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	auto node = reinterpret_cast<RConfigNode *>(data);
	SleighArchitecture::shutdown();
	SleighArchitecture::specpaths = FileManage();
	if(node->value && *node->value)
		SleighArchitecture::scanForSleighDirectories(node->value);
	return true;
}

static void SetInitialSleighHome(RConfig *cfg)
{
	// user-set, for example from .radare2rc
	if(!cfg_var_sleighhome.GetString(cfg).empty())
		return;

	// SLEIGHHOME env
	const char *sleighhomepath = getenv("SLEIGHHOME");
	if(sleighhomepath && *sleighhomepath)
	{
		cfg_var_sleighhome.Set(cfg, sleighhomepath);
		return;
	}

#ifdef R2GHIDRA_SLEIGHHOME_DEFAULT
	if(r_file_is_directory(R2GHIDRA_SLEIGHHOME_DEFAULT))
	{
		cfg_var_sleighhome.Set(cfg, R2GHIDRA_SLEIGHHOME_DEFAULT);
		return;
	}
#endif

	// r2pm-installed ghidra
	char *homepath = r_str_home(".local/share/radare2/r2pm/git/ghidra");
	if(homepath && r_file_is_directory(homepath))
	{
		cfg_var_sleighhome.Set(cfg, homepath);
	}
	r_mem_free (homepath);
}

static int r2ghidra_init(void *user, const char *cmd)
{
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	startDecompilerLibrary(nullptr);

	auto *rcmd = reinterpret_cast<RCmd *>(user);
	auto *core = reinterpret_cast<RCore *>(rcmd->data);
	RConfig *cfg = core->config;
	r_config_lock (cfg, false);
	for(const auto var : ConfigVar::GetAll())
	{
		RConfigNode *node;
		if(var->GetCallback())
			node = r_config_set_cb(cfg, var->GetName(), var->GetDefault(), var->GetCallback());
		else
			node = r_config_set(cfg, var->GetName(), var->GetDefault());
		r_config_node_desc(node, var->GetDesc());
	}
	r_config_lock (cfg, true);

	SetInitialSleighHome(cfg);
	return true;
}

static int r2ghidra_fini(void *user, const char *cmd)
{
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	shutdownDecompilerLibrary();
	return true;
}

RCorePlugin r_core_plugin_ghidra = {
	/* .name = */ "r2ghidra",
	/* .desc = */ "Ghidra integration",
	/* .license = */ "GPL3",
	/* .author = */ "thestr4ng3r",
	/* .version = */ nullptr,
	/*.call = */ r2ghidra_cmd,
	/*.init = */ r2ghidra_init,
	/*.fini = */ r2ghidra_fini
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_CORE,
	/* .data = */ &r_core_plugin_ghidra,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr
#if R2_VERSION_MAJOR >= 4 && R2_VERSION_MINOR >= 2
	, "r2ghidra-dec"
#endif
};
#endif
