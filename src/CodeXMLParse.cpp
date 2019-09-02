
#include "CodeXMLParse.h"
#include "AnnotatedCode.h"
#include <funcdata.hh>
#include <r_util.h>
#include <pugixml.hpp>
#include <sstream>
#include <string>

struct ParseCodeXMLContext
{
	Funcdata *func;
	std::map<uintm, PcodeOp *> ops;

	explicit ParseCodeXMLContext(Funcdata *func) : func(func)
	{
		for(auto it=func->beginOpAll(); it!=func->endOpAll(); it++)
			ops[it->first.getTime()] = it->second;
	}
};

#define ANNOTATOR_PARAMS pugi::xml_node node, ParseCodeXMLContext *ctx, std::vector<RCodeAnnotation> *out
#define ANNOTATOR [](ANNOTATOR_PARAMS) -> void

void AnnotateOpref(ANNOTATOR_PARAMS)
{
	pugi::xml_attribute attr = node.attribute("opref");
	if(attr.empty())
		return;
	unsigned long long opref = attr.as_ullong(ULLONG_MAX);
	if(opref == ULLONG_MAX)
		return;
	auto opit = ctx->ops.find((uintm)opref);
	if(opit == ctx->ops.end())
		return;
	auto op = opit->second;

	out->emplace_back();
	auto &annotation = out->back();
	annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_OFFSET;
	annotation.offset.offset = op->getAddr().getOffset();
}

static const std::map<std::string, void (*)(ANNOTATOR_PARAMS)> annotators = {
	{ "statement", AnnotateOpref },
	{ "op", AnnotateOpref }
};

//#define TEST_UNKNOWN_NODES

static void ParseNode(pugi::xml_node node, ParseCodeXMLContext *ctx, std::ostream &stream, RAnnotatedCode *code)
{
	if(node.type() == pugi::xml_node_type::node_pcdata)
	{
		stream << node.value();
		return;
	}

	std::vector<RCodeAnnotation> annotations;
#ifdef TEST_UNKNOWN_NODES
	bool close_test = false;
	static const std::set<std::string> boring_tags = { "syntax" };
#endif

	if(strcmp(node.name(), "break") == 0)
	{
		stream << "\n";
		stream << std::string(node.attribute("indent").as_uint(0), ' ');
	}
	else
	{
		auto it = annotators.find(node.name());
		if(it != annotators.end())
		{
			it->second(node, ctx, &annotations);
			for(auto &annotation : annotations)
				annotation.start = stream.tellp();
		}
#ifdef TEST_UNKNOWN_NODES
		else if(boring_tags.find(node.name()) == boring_tags.end())
		{
			close_test = true;
			stream << "<" << node.name();
			for(pugi::xml_attribute attr : node.attributes())
				stream << " " << attr.name() << "=\"" << attr.value() << "\""; // unescaped, but who cares
			stream << ">";
		}
#endif
	}

	for(pugi::xml_node child : node)
		ParseNode(child, ctx, stream, code);

	for(auto &annotation : annotations)
	{
		annotation.end = stream.tellp();
		r_annotated_code_add_annotation(code, &annotation);
	}

#ifdef TEST_UNKNOWN_NODES
	if(close_test)
		stream << "</" << node.name() << ">";
#endif
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

	ParseCodeXMLContext ctx(func);
	ParseNode(doc.child("function"), &ctx, ss, code);

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