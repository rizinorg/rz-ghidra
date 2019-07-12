/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <r_anal.h>

#define CMD_PREFIX "pdg"

static void print_usage(const RCore* const core) {
	const char* help[] = {
			"Usage: " CMD_PREFIX, "",	"# Ghidra integration",
			NULL
	};

	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}


static void _cmd(RCore *core, const char *input) {
	switch (*input) {
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
	RCmd *rcmd = (RCmd*)user;
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
