/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2Architecture.h"

#include <libdecomp.hh>

#include <r_core.h>

#define CMD_PREFIX "pdg"

static void print_usage(const RCore *const core) {
	const char* help[] = {
		"Usage: " CMD_PREFIX, "", "# Native Ghidra decompiler plugin",
		CMD_PREFIX, "", "# Decompile current function with the Ghidra decompiler",
		CMD_PREFIX, "x", "# Dump the XML of the current decompiled function",
		"Environment:", "", "",
		"%SLEIGHHOME" , "", "# Path to ghidra build root directory",
		NULL
	};

	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

enum class DecompileMode { DEFAULT, XML, DEBUG_XML };

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
			case DecompileMode::DEBUG_XML:
				arch.saveXml(out_stream);
				break;
		}

		if(mode == DecompileMode::XML)
			out_stream << "</code></result>";

		r_cons_print(out_stream.str().c_str());
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
