/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2Architecture.h"

#include <libdecomp.hh>
#include <printc.hh>
#include "R2PrintC.h"

#include <r_core.h>

#define CMD_PREFIX "pdg"

static void print_usage(const RCore *const core) {
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

static void decompile(RCore *core, DecompileMode mode) {
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

		auto r2PrintC = dynamic_cast<R2PrintC *>(arch.print_with_offsets);
		if (r2PrintC)
		{
			r2PrintC->setCPlusPlusStyleComments();
			r2PrintC->setSpaceAfterComma(true);
			r2PrintC->setNewlineBeforeOpeningBrace(true);
			r2PrintC->setNewlineAfterPrototype(false);
			r2PrintC->setIndentIncrement(4);
			r2PrintC->setLineCommentIndent(0);
		}

		if(auto printC = dynamic_cast<PrintC *>(arch.print))
		{
			printC->setCPlusPlusStyleComments();
			printC->setSpaceAfterComma(true);
			printC->setNewlineBeforeOpeningBrace(true);
			printC->setNewlineAfterPrototype(false);
			printC->setIndentIncrement(4);
			printC->setLineCommentIndent(0);
			printC->setMaxLineSize(120);
		}

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
			vector<vector<Address>> offsets = r2PrintC->getOffsets();
			size_t ln = 0;
			while (getline(out_stream, line))
			{
				if(ln >= offsets.size()) break;
				if(offsets[ln].size())
				{
					char hexstring[11] = {};
					offset = offsets[ln].front().getOffset();
					snprintf(hexstring, 10, "0x%08x" PRIx64, offset);
					line_stream << "    " <<  hexstring << "    |" << line << "\n";
				}
				else
				{
					line_stream << "                 |" << line << "\n";
				}
				ln+=1;
			}
			r_cons_print(line_stream.str().c_str());
		}
		else if(mode == DecompileMode::STATEMENTS)
		{
			for (auto const& addr : r2PrintC->getStatementsMap())
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

				comment_stream << "s " <<  "0x" << std::hex << addr.first.getOffset() << "\n";
				comment_stream << "\"CC " << statement.c_str() <<  "\"\n";
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

static void _cmd(RCore *core, const char *input) {
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

static int r2ghidra_cmd(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, CMD_PREFIX, strlen(CMD_PREFIX))) {
		_cmd (core, input + 3);
		return true;
	}
	return false;
}

static int r2ghidra_init(void *user, const char *cmd) {
	const char *sleighhomepath = getenv("SLEIGHHOME");
	char *homepath = NULL;
	if (!sleighhomepath) {
		homepath = r_str_home (".local/share/radare2/r2pm/git/ghidra");
		sleighhomepath = homepath;
	}
	startDecompilerLibrary(sleighhomepath);
	r_free (homepath);
	return true;
}

static int r2ghidra_fini(void *user, const char *cmd) {
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
