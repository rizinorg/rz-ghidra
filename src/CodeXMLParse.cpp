
#include "CodeXMLParse.h"
#include <r_util/r_annotated_code.h>

#ifdef LoadImage
#undef LoadImage
#endif

#include <funcdata.hh>
#include <r_util.h>
#include <pugixml.hpp>
#include <sstream>
#include <string>

struct ParseCodeXMLContext
{
	Funcdata *func;
	std::map<uintm, PcodeOp *> ops;
	std::map<unsigned long long, Varnode *> varnodes;
	std::map<unsigned long long, Symbol *> symbols;
	
	explicit ParseCodeXMLContext(Funcdata *func) : func(func)
	{
		for(auto it=func->beginOpAll(); it!=func->endOpAll(); it++)
			ops[it->first.getTime()] = it->second;
		for(auto it = func->beginLoc(); it != func->endLoc(); it++)
			varnodes[(*it)->getCreateIndex()] = *it;

		ScopeLocal *mapLocal = func->getScopeLocal();
		MapIterator iter = mapLocal->begin();
		MapIterator enditer = mapLocal->end();
		for (; iter!=enditer; ++iter)
		{
			const SymbolEntry *entry = *iter;
			Symbol *sym = entry->getSymbol();
			symbols[sym->getId()] = sym;
		}
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
void AnnotateFunctionName(ANNOTATOR_PARAMS)
{
	const char *func_name = node.child_value();
	if(!func_name)
		return;
	RCodeAnnotation annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_FUNCTION_NAME;
	pugi::xml_attribute attr = node.attribute("opref");
	if(attr.empty())
	{
		if(ctx->func->getName() == func_name)
		{
			annotation.reference.name = strdup(ctx->func->getName().c_str());
			annotation.reference.offset = ctx->func->getAddress().getOffset();
			out->push_back(annotation);
			// Code below makes an offset annotation for the function name(for the currently decompiled function)
			RCodeAnnotation offsetAnnotation = {};
			offsetAnnotation.type = R_CODE_ANNOTATION_TYPE_OFFSET;
			offsetAnnotation.offset.offset = annotation.reference.offset;
			out->push_back(offsetAnnotation);
		}
		return;
	}
	unsigned long long opref = attr.as_ullong(ULLONG_MAX);
	if(opref == ULLONG_MAX)
	{
		return;
	}
	auto opit = ctx->ops.find((uintm)opref);
	if(opit == ctx->ops.end())
	{
		return;	
	}
	PcodeOp *op = opit->second;
	FuncCallSpecs *call_func_spec = ctx->func->getCallSpecs(op);
	if(call_func_spec)
	{
		annotation.reference.name = strdup(call_func_spec->getName().c_str());
		annotation.reference.offset = call_func_spec->getEntryAddress().getOffset();
		out->push_back(annotation);
	}
}

void AnnotateCommentOffset(ANNOTATOR_PARAMS)
{
	pugi::xml_attribute attr = node.attribute("off");
	if(attr.empty())
		return;
	unsigned long long off = attr.as_ullong(ULLONG_MAX);
	if(off == ULLONG_MAX)
		return;
	out->emplace_back();
	auto &annotation = out->back();
	annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_OFFSET;
	annotation.offset.offset = off;
}

/**
 * Translate Ghidra's color annotations, which are essentially
 * loose token classes of the high level decompiled source code.
 **/
void AnnotateColor(ANNOTATOR_PARAMS)
{
	pugi::xml_attribute attr = node.attribute("color");
	if (attr.empty())
		return;

	std::string color = attr.as_string();
	if (color == "")
		return;

	RSyntaxHighlightType type;
	if (color == "keyword")
		type = R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD;
	else if (color == "comment")
		type = R_SYNTAX_HIGHLIGHT_TYPE_COMMENT;
	else if (color == "type")
		type = R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE;
	else if (color == "funcname")
		type = R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME;
	else if (color == "param")
		type = R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER;
	else if (color == "var")
		type = R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE;
	else if (color == "const")
		type = R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE;
	else if (color == "global")
		type = R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE;
	else
		return;
	RCodeAnnotation annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT;
	annotation.syntax_highlight.type = type;
	out->push_back(annotation);
}

void AnnotateGlobalVariable(Varnode *varnode, std::vector<RCodeAnnotation> *out)
{
	RCodeAnnotation annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_GLOBAL_VARIABLE;
	annotation.reference.offset = varnode->getOffset();
	out->push_back(annotation);
}

void AnnotateConstantVariable(Varnode *varnode, std::vector<RCodeAnnotation> *out)
{
	RCodeAnnotation annotation = {};
	annotation.type = R_CODE_ANNOTATION_TYPE_CONSTANT_VARIABLE;
	annotation.reference.offset = varnode->getOffset();
	out->push_back(annotation);
}

// Annotates local variables and function parameters
void AnnotateLocalVariable(Symbol *symbol, std::vector<RCodeAnnotation> *out)
{
	if(symbol == (Symbol *)0)
		return;
	RCodeAnnotation annotation = {};
	annotation.variable.name = strdup(symbol->getName().c_str());
	if(symbol->getCategory() == 0)
		annotation.type = R_CODE_ANNOTATION_TYPE_FUNCTION_PARAMETER;
	else
		annotation.type = R_CODE_ANNOTATION_TYPE_LOCAL_VARIABLE;
	out->push_back(annotation);
}

void AnnotateVariable(ANNOTATOR_PARAMS)
{
	pugi::xml_attribute attr = node.attribute("varref");
	if(attr.empty())
	{
		auto node_parent = node.parent();
		if(strcmp(node_parent.name(), "vardecl") == 0)
		{
			pugi::xml_attribute attributeSymbolId = node_parent.attribute("symref");
			unsigned long long symref = attributeSymbolId.as_ullong(ULLONG_MAX);
			Symbol *symbol = ctx->symbols[symref];
			AnnotateLocalVariable(symbol, out);
		}
		return;
	}
	unsigned long long varref = attr.as_ullong(ULLONG_MAX);
	if(varref == ULLONG_MAX)
		return;
	auto varrefnode = ctx->varnodes.find(varref);
	if(varrefnode == ctx->varnodes.end())
		return;
	Varnode *varnode = varrefnode->second;
	if (varnode->getHigh()->isPersist() && varnode->getHigh()->isAddrTied())
		AnnotateGlobalVariable(varnode, out);
	else if (varnode->getHigh()->isConstant() && varnode->getHigh()->getType()->getMetatype() == TYPE_PTR) 
		AnnotateConstantVariable(varnode, out);
	else if (!varnode->getHigh()->isPersist())
		AnnotateLocalVariable(varnode->getHigh()->getSymbol(), out);
}

static const std::map<std::string, std::vector <void (*)(ANNOTATOR_PARAMS)> > annotators = {
	{ "statement", { AnnotateOpref } },
	{ "op", { AnnotateOpref, AnnotateColor } },
	{ "comment", { AnnotateCommentOffset, AnnotateColor } },
	{ "variable", { AnnotateVariable, AnnotateColor } },
	{ "funcname", { AnnotateFunctionName, AnnotateColor } },
	{ "type", { AnnotateColor } },
	{ "syntax", { AnnotateColor } }
};

//#define TEST_UNKNOWN_NODES

/**
 * Ghidra returns an annotated AST of the decompiled high-level language code.
 * The AST is saved in XML format.
 *
 * This function is a DFS traversal over Ghidra's AST.
 * It parses some of the annotatations (e.g. decompilation offsets, token classes, ..)
 * and translates them into a suitable format
 * that can be natively saved in the RAnnotatedCode structure.
 **/
static void ParseNode(pugi::xml_node node, ParseCodeXMLContext *ctx, std::ostream &stream, RAnnotatedCode *code)
{
	// A leaf is an XML node which contains parts of the high level decompilation language
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
			auto &callbacks = it->second;
			for (auto &callback : callbacks)
				callback(node, ctx, &annotations);
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

	// an annotation applies for a node an all its children
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
