/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2Architecture.h"

#include <libdecomp.hh>
#include <printc.hh>
#include "R2PrintC.h"

#include <r_core.h>

#include <vector>

#define CMD_PREFIX "pdg"
#define CFG_PREFIX "r2ghidra"

struct ConfigVar
{
	private:
		static std::vector<const ConfigVar *> vars_all;

		const std::string name;
		const char * const defval;
		const char * const desc;

	public:
		ConfigVar(const char *var, const char *defval, const char *desc)
			: name(std::string(CFG_PREFIX) + "." + var), defval(defval), desc(desc) { vars_all.push_back(this); }

		const char *GetName() const 				{ return name.c_str(); }
		const char *GetDefault() const 				{ return defval; }
		const char *GetDesc() const 				{ return desc; }

		ut64 GetInt(RConfig *cfg) const				{ return r_config_get_i(cfg, name.c_str()); }
		bool GetBool(RConfig *cfg) const			{ return GetInt(cfg) != 0; }
		std::string GetString(RConfig *cfg) const	{ return r_config_get(cfg, name.c_str()); }

		static const std::vector<const ConfigVar *> &GetAll()	{ return vars_all; }
};
std::vector<const ConfigVar *> ConfigVar::vars_all;

static const ConfigVar cfg_var_cmt_cpp		("cmt.cpp",		"true",		"C++ comment style");
static const ConfigVar cfg_var_cmt_indent	("cmt.indent",	"4",		"Comment indent");
static const ConfigVar cfg_var_nl_brace		("nl.brace",	"false",	"Newline before opening '{'");
static const ConfigVar cfg_var_nl_else		("nl.else",		"false",	"Newline before else");
static const ConfigVar cfg_var_indent		("indent",		"4",		"Indent increment");
static const ConfigVar cfg_var_linelen		("linelen",		"120",		"Max line length");

static void print_usage(const RCore *const core)
{
	const char* help[] = {
		"Usage: " CMD_PREFIX, "", "# Native Ghidra decompiler plugin",
		CMD_PREFIX, "", "# Decompile current function with the Ghidra decompiler",
		CMD_PREFIX, "d", "# Dump the debug XML Dump",
		CMD_PREFIX, "x", "# Dump the XML of the current decompiled function",
		CMD_PREFIX, "o", "# Decompile current function side by side with offsets",
		CMD_PREFIX, "*", "# Decompiled code is returned to r2 as comment",
		"Environment:", "", "",
		"%SLEIGHHOME" , "", "# Path to ghidra build root directory",
		NULL
	};

	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

enum class DecompileMode { DEFAULT, XML, DEBUG_XML, OFFSET, STATEMENTS };

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

static void decompile(RCore *core, DecompileMode mode)
{
	RAnalFunction *function = r_anal_get_fcn_in(core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if(!function)
	{
		eprintf("No function\n");
		return;
	}

#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		R2Architecture arch(core);
		DocumentStorage store;
		arch.init(store);

		std::stringstream out_stream;
		arch.print->setOutputStream(&out_stream);
		arch.print_with_offsets->setOutputStream(&out_stream);

		auto r2_print_c = dynamic_cast<R2PrintC *>(arch.print_with_offsets);
		ApplyPrintCConfig(core->config, r2_print_c);
		ApplyPrintCConfig(core->config, dynamic_cast<PrintC *>(arch.print));

		Funcdata *func = arch.symboltab->getGlobalScope()->findFunction(Address(arch.getDefaultSpace(), function->addr));
		if(!func)
		{
			eprintf("No function in Scope\n");
			return;
		}

		int res = arch.allacts.getCurrent()->perform(*func);
		if (res<0)
			eprintf("break\n");
		/*else
		{
			eprintf("Decompilation complete\n");
			if(res==0)
				eprintf("(no change)\n");
		}*/

		for(const auto &warning : arch.getWarnings())
			func->warningHeader("[r2ghidra] " + warning);

		if(mode == DecompileMode::XML)
		{
			arch.print->setXML(true);
			out_stream << "<result><function>";
			func->saveXml(out_stream, true);
			out_stream << "</function><code>";
		}

		switch(mode)
		{
			case DecompileMode::XML:
			case DecompileMode::DEFAULT:
				arch.print->docFunction(func);
				break;
			case DecompileMode::STATEMENTS:
			case DecompileMode::OFFSET:
				arch.print_with_offsets->docFunction(func);
				break;
			case DecompileMode::DEBUG_XML:
				arch.saveXml(out_stream);
				break;
		}

		if(mode == DecompileMode::OFFSET)
		{
			ut64 offset;
			string line;
			std::stringstream line_stream;
			vector<vector<Address>> offsets = r2_print_c->getOffsets();
			size_t ln = 0;
			while (getline(out_stream, line))
			{
				if(ln >= offsets.size()) break;
				if(offsets[ln].size())
				{
					offset = offsets[ln].front().getOffset();
					std::stringstream offset_stream;
					offset_stream << "0x" << std::setfill('0') << std::setw(10) << std::hex << offset;
					line_stream << "    " <<  offset_stream.str() << "    |" << line << "\n";
				}
				else
				{
					line_stream << "                    |" << line << "\n";
				}
				ln+=1;
			}
			r_cons_print(line_stream.str().c_str());
		}
		else if(mode == DecompileMode::STATEMENTS)
		{
			for (auto const& addr : r2_print_c->getStatementsMap())
			{
				string statement = addr.second;
				stringstream comment_stream;
				size_t start_tag = statement.find("R2_OFFSET_START");
				if(start_tag != -1)
				{
					size_t end_tag = statement.find("R2_OFFSET_STOP") + 15;
					statement.erase(start_tag, end_tag-start_tag);
				}
				statement.erase(std::remove(statement.begin(), statement.end(), '\n'), statement.end() );

				char *b64statement = r_base64_encode_dyn(statement.c_str(), statement.size());
				comment_stream << "s " << "0x" << std::hex << addr.first.getOffset() << "\n";
				comment_stream << "CCu base64:" << b64statement << "\n";
				r_cons_print(comment_stream.str().c_str());
			}
		}
		else
		{
			if(mode == DecompileMode::XML)
			{
				out_stream << "</code></result>";
			}
			r_cons_print(out_stream.str().c_str());
		}
#ifndef DEBUG_EXCEPTIONS
	}
	catch(LowlevelError error)
	{
		eprintf("Ghidra Decompiler Error: %s\n", error.explain.c_str());
	}
#endif
}

static void _cmd(RCore *core, const char *input)
{
	switch (*input) {
		case 'd':
			decompile(core, DecompileMode::DEBUG_XML);
			break;
		case '\0':
			decompile(core, DecompileMode::DEFAULT);
			break;
		case 'x':
			decompile(core, DecompileMode::XML);
			break;
		case 'o':
			decompile(core, DecompileMode::OFFSET);
			break;
		case '*':
			decompile(core, DecompileMode::STATEMENTS);
			break;
		default:
			print_usage(core);
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

static int r2ghidra_init(void *user, const char *cmd)
{
	auto *rcmd = reinterpret_cast<RCmd *>(user);
	auto *core = reinterpret_cast<RCore *>(rcmd->data);
	RConfig *cfg = core->config;
	r_config_lock (cfg, false);
	for(const auto var : ConfigVar::GetAll())
		r_config_node_desc(r_config_set(cfg, var->GetName(), var->GetDefault()), var->GetDesc());
	r_config_lock (cfg, true);

	const char *sleighhomepath = getenv("SLEIGHHOME");
	char *homepath = NULL;
	if(!sleighhomepath)
	{
		homepath = r_str_home (".local/share/radare2/r2pm/git/ghidra");
		sleighhomepath = homepath;
	}
	startDecompilerLibrary(sleighhomepath);
	r_free (homepath);
	return true;
}

static int r2ghidra_fini(void *user, const char *cmd)
{
	shutdownDecompilerLibrary();
	return true;
}

RCorePlugin r_core_plugin_ghidra = {
	.name = "r2ghidra",
	.desc = "Ghidra integration",
	.license = "GPL3",
	.call = r2ghidra_cmd,
	.init = r2ghidra_init
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_ghidra,
	.version = R2_VERSION
};
#endif
