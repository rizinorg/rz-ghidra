/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2GhidraDecompiler.h"

#include <Cutter.h>

#include <QtXml>

class R2GhidraXMLParser
{
	private:
		class ParseError: public std::exception
		{
			private:
				QString message;

			public:
				explicit ParseError(const QString &message) { this->message = message; }
				QString getMessage() const { return message; }
		};

		QXmlStreamReader xml;
		DecompiledCode code;
		QMap<ut64, ut64> opRefAddr;

		void parseInternal();

		void parseFunction();
		void parseFunctionAST();
		void parseFunctionBlock();
		void parseFunctionOp();

		void parseCode();

	public:
		R2GhidraXMLParser(const QString &xmlString);
		DecompiledCode parse();
};

R2GhidraXMLParser::R2GhidraXMLParser(const QString &xmlString)
		: xml(xmlString)
{
}

void R2GhidraXMLParser::parseInternal()
{
	if (!xml.readNextStartElement() || xml.name() != "result") {
		throw ParseError("Expected result tag, got " + xml.name());
	}

	if (!xml.readNextStartElement() || xml.name() != "function") {
		throw ParseError("Expected function tag, got " + xml.name());
	}

	parseFunction();

	if (!xml.readNextStartElement() || xml.name() != "code") {
		throw ParseError("Expected code tag, got " + xml.name());
	}

	parseCode();

	xml.skipCurrentElement();
}

void R2GhidraXMLParser::parseFunction()
{
	if (!xml.readNextStartElement() || xml.name() != "function") {
		throw ParseError("Expected function tag, got " + xml.name());
	}

	while (!xml.atEnd()) {
		auto token = xml.readNext();
		if (token == QXmlStreamReader::EndElement) {
			break;
		}

		if (token == QXmlStreamReader::StartElement) {
			if (xml.name() == "ast") {
				parseFunctionAST();
			} else {
				xml.skipCurrentElement();
			}
		}
	}

	xml.skipCurrentElement();
}

void R2GhidraXMLParser::parseFunctionAST()
{
	while (!xml.atEnd()) {
		auto token = xml.readNext();
		if (token == QXmlStreamReader::EndElement) {
			break;
		}

		if (token == QXmlStreamReader::StartElement) {
			if (xml.name() == "block") {
				parseFunctionBlock();
			} else {
				xml.skipCurrentElement();
			}
		}
	}
}

void R2GhidraXMLParser::parseFunctionBlock()
{
	while (!xml.atEnd()) {
		auto token = xml.readNext();
		if (token == QXmlStreamReader::EndElement) {
			break;
		}

		if (token == QXmlStreamReader::StartElement) {
			if (xml.name() == "op") {
				parseFunctionOp();
			} else {
				xml.skipCurrentElement();
			}
		}
	}
}

void R2GhidraXMLParser::parseFunctionOp()
{
	while (!xml.atEnd()) {
		auto token = xml.readNext();
		if (token == QXmlStreamReader::EndElement) {
			break;
		}

		if (token == QXmlStreamReader::StartElement) {
			if (xml.name() == "seqnum") {
				bool seqnumOk;
				ut64 seqnum = xml.attributes().value("uniq").toInt(&seqnumOk, 0);
				bool addrOk;
				ut64 addr = xml.attributes().value("offset").toInt(&addrOk, 0);
				if (seqnumOk && addrOk) {
					opRefAddr[seqnum] = addr;
				}
			}
			xml.skipCurrentElement();
		}
	}
}

void R2GhidraXMLParser::parseCode()
{
	if (!xml.readNextStartElement() || xml.name() != "function") {
		throw ParseError("Expected function tag, got " + xml.name());
	}

	DecompiledCode::Line line;

	auto flushLine = [this, &line]() {
		code.lines.append(line);
		line = DecompiledCode::Line();
	};

	int depth = 1;
	while (!xml.atEnd() && depth > 0) {
		auto token = xml.readNext();
		switch (token) {
			case QXmlStreamReader::StartElement:
				depth++;
				if (xml.name() == "break") {
					flushLine();
					int indent = xml.attributes().value("indent").toInt(nullptr, 0);
					line.str += QString(" ").repeated(indent);
				}
				else if (xml.name() == "statement") {
					bool ok;
					ut64 opref = xml.attributes().value("opref").toInt(&ok, 0);
					if (ok) {
						auto it = opRefAddr.find(opref);
						if (it != opRefAddr.end()) {
							line.addr = it.value();
						}
					}
				}
				break;
			case QXmlStreamReader::EndElement:
				depth--;
				break;
			case QXmlStreamReader::Characters:
				line.str += xml.text();
				break;
			default:
				break;
		}
	}

	flushLine();

	xml.skipCurrentElement();
}

DecompiledCode R2GhidraXMLParser::parse()
{
	try {
		parseInternal();
		if(xml.hasError()) {
			code.lines.clear();
			code.lines.append(DecompiledCode::Line("XML Error: " + xml.errorString()));
		}
	} catch (const ParseError &err) {
		code.lines.clear();
		code.lines.append(DecompiledCode::Line("XML Parse Error: " + err.getMessage() + " at " + QString::number(xml.characterOffset())));
	}
	return code;
}


R2GhidraDecompiler::R2GhidraDecompiler(QObject *parent)
	: Decompiler("r2ghidra", "Ghidra", parent)
{
}

DecompiledCode R2GhidraDecompiler::decompileAt(RVA addr)
{
	auto xmlString = Core()->cmd("pdgx @ " + QString::number(addr));

	QDomDocument doc;
	doc.setContent(xmlString);

	R2GhidraXMLParser parser(xmlString);
	return parser.parse();
}
