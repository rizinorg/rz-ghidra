// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "PrettyXmlEncode.h"

using namespace ghidra;

void PrettyXmlEncode::indent()
{
	for(int i = 0; i < depth; i++)
		outStream << "  ";
}

void PrettyXmlEncode::openElement(const ElementId &elemId)
{
	if(elementTagIsOpen)
		outStream << ">\n";
	else
		elementTagIsOpen = true;
	indent();
	depth++;
	outStream << '<' << elemId.getName();
}

void PrettyXmlEncode::closeElement(const ElementId &elemId)
{
	depth--;
	if(elementTagIsOpen)
	{
		outStream << "/>\n";
		elementTagIsOpen = false;
	}
	else
	{
		indent();
		outStream << "</" << elemId.getName() << ">\n";
	}
}

