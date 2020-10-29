/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "RzGhidraDecompiler.h"
#include "RzGhidraPlugin.h"

void RzGhidraPlugin::setupPlugin()
{
}

void RzGhidraPlugin::setupInterface(MainWindow *)
{
}

void RzGhidraPlugin::registerDecompilers()
{
	Core()->registerDecompiler(new RzGhidraDecompiler(Core()));
}