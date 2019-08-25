
#include "CodeXMLParse.h"
#include <funcdata.hh>
#include <r_util.h>
#include <pugixml.hpp>
#include <sstream>
#include <string>

static void ParseNode(pugi::xml_node node, Funcdata *func, std::ostream &stream, RAnnotatedCode *code)
{
	if(node.type() == pugi::xml_node_type::node_pcdata)
	{
		stream << node.value();
		return;
	}

	if(strcmp(node.name(), "break") == 0)
	{
		stream << "\n";
		stream << std::string(node.attribute("indent").as_uint(0), ' ');
	}

	for(pugi::xml_node child : node)
		ParseNode(child, func, stream, code);
}

R_API RAnnotatedCode *ParseCodeXML(Funcdata *func, const char *xml)
{
	pugi::xml_document doc;
	if(!doc.load_string(xml, pugi::parse_default | pugi::parse_ws_pcdata))
		return nullptr;

	std::stringstream ss;
	RAnnotatedCode *code = r_annotated_code_new(nullptr);
	if(!code)
		return nullptr;

	ParseNode(doc.child("function"), func, ss, code);

	std::string str = ss.str();
	code->code = reinterpret_cast<char *>(r_malloc(str.length() + 1));
	if(!code->code)
	{
		r_annotated_code_free(code);
		return nullptr;
	}
	memcpy(code->code, str.c_str(), str.length());
	code->code[str.length()] = '\0';
	return code;
}