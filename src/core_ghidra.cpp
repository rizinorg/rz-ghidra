/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2Architecture.h"

#include <libdecomp.hh>

#include <r_core.h>

#define CMD_PREFIX "pdg"

static void print_usage(const RCore *const core) {
	const char* help[] = {
			"Usage: " CMD_PREFIX, "",	"# Ghidra integration",
			NULL
	};

	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

static void decompile(RCore *core) {
	RAnalFunction *function = r_anal_get_fcn_in(core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	if(!function)
	{
		eprintf("No function\n");
		return;
	}

	try
	{
		R2Architecture arch(core);
		DocumentStorage store;
		arch.init(store);

		arch.print->setOutputStream(&cout);

		Funcdata dec_func(function->name,
				arch.symboltab->getGlobalScope(),
				Address(arch.getDefaultSpace(), function->addr));
		int res = arch.allacts.getCurrent()->perform(dec_func);
		if (res<0)
			eprintf("break\n");
		else
		{
			eprintf("Decompilation complete\n");
			if(res==0)
				eprintf("(no change)\n");
		}

		arch.print->docFunction(&dec_func);
	}
	catch(LowlevelError error)
	{
		eprintf("Ghidra Decompiler Error: %s\n", error.explain.c_str());
	}
}

static void _cmd(RCore *core, const char *input) {
	switch (*input) {
		case '\0':
			decompile(core);
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
	//RCmd *rcmd = (RCmd*)user;
	const char *sleighhomepath = getenv("SLEIGHHOME");
	startDecompilerLibrary(sleighhomepath);
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
