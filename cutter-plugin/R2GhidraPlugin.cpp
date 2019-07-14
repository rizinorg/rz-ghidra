/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2GhidraDecompiler.h"
#include "R2GhidraPlugin.h"

void R2GhidraPlugin::setupPlugin()
{
}

void R2GhidraPlugin::setupInterface(MainWindow *)
{
}

void R2GhidraPlugin::registerDecompilers()
{
	Core()->registerDecompiler(new R2GhidraDecompiler(Core()));
}