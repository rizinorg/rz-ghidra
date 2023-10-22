// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef PRETTY_XML_ENCODE_H
#define PRETTY_XML_ENCODE_H

#include <marshal.hh>

class PrettyXmlEncode: public ghidra::XmlEncode
{
	private:
		int depth = 0;
		void indent();

	public:
		PrettyXmlEncode(std::ostream &s) : XmlEncode(s) {}
		void openElement(const ghidra::ElementId &elemId) override;
		void closeElement(const ghidra::ElementId &elemId) override;
};

#endif
