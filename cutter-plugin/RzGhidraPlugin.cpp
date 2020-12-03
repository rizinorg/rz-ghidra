// SPDX-License-Identifier: LGPL-3.0-or-later

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