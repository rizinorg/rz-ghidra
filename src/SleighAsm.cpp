// SPDX-FileCopyrightText: 2020-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "SleighAsm.h"
#include "ArchMap.h"

using namespace ghidra;

AsmLoadImage::AsmLoadImage()
	: LoadImage("rizin_asm"), buf(rz_buf_new_sparse(0xff), rz_buf_free)
{
}

void AsmLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr)
{
	rz_buf_read_at(buf.get(), addr.getOffset(), ptr, size);
}

void AsmLoadImage::resetBuffer(ut64 offset, const ut8 *data, size_t size)
{
	rz_buf_resize(buf.get(), 0); // clears the buffer
	rz_buf_write_at(buf.get(), offset, data, size);
}

void SleighAsm::init(const char *cpu, int bits, bool bigendian, RzConfig *cfg)
{
	if(description.empty())
	{
		/* Initialize sleigh spec files */
		scanSleigh(getSleighHome(cfg));
		collectSpecfiles();
	}

	std::string new_sleigh_id = SleighIdFromSleighAsmConfig(cpu, bits, bigendian, description);

	if(!sleigh_id.empty() && sleigh_id == new_sleigh_id)
		return;

	initInner(new_sleigh_id);
}

void SleighAsm::initInner(std::string sleigh_id)
{
	/* Initialize Sleigh */
	docstorage = std::move(DocumentStorage());
	resolveArch(sleigh_id);
	buildSpecfile(docstorage);
	context = std::move(ContextInternal());
	trans.reset(&loader, &context);
	trans.initialize(docstorage);
	parseProcConfig(docstorage);
	parseCompConfig(docstorage);
	alignment = trans.getAlignment();
	trans.clearCache();
	initRegMapping();

	this->sleigh_id = sleigh_id;
}

static void parseProto(const Element *el, std::vector<std::string> &arg_names,
		std::vector<std::string> &ret_names)
{
	if(el->getName() != "prototype")
		throw LowlevelError("Expecting <prototype> tag");

	const List &list(el->getChildren());
	for(auto iter = list.begin(); iter != list.end(); ++iter)
	{
		const Element *subnode = *iter;

		if(subnode->getName() == "input" || subnode->getName() == "output")
		{
			const List &flist(subnode->getChildren());
			for(auto fiter = flist.begin(); fiter != flist.end(); ++fiter)
			{
				const Element *subel = *fiter;
				const Element *reg = *subel->getChildren().begin();
				if(subel->getName() == "pentry" && reg->getName() == "register")
				{
					int4 num = subel->getNumAttributes(), i = 0;
					for(; i < num; ++i)
					{
						if(subel->getAttributeName(i) == "metatype" &&
						   subel->getAttributeValue(i) == "float")
							break;
					}
					if(i != num)
						continue;

					for(int p = 0; p < reg->getNumAttributes(); ++p)
					{
						if(reg->getAttributeName(p) == "name")
						{
							if(subnode->getName() == "input")
								arg_names.push_back(reg->getAttributeValue(p));
							else
								ret_names.push_back(reg->getAttributeValue(p));
						}
					}
				}
			}
		}
	}
}

static void parseDefaultProto(const Element *el, std::vector<std::string> &arg_names,
		std::vector<std::string> &ret_names)
{
	const List &list(el->getChildren());
	List::const_iterator iter;

	for(iter = list.begin(); iter != list.end(); ++iter)
	{
		// Decompiler will parse the same entry, and exit if multiple exists.
		arg_names.clear();
		ret_names.clear();
		parseProto(*iter, arg_names, ret_names);
	}
}

void SleighAsm::parseCompConfig(DocumentStorage &store)
{
	const Element *el = store.getTag("compiler_spec");
	if(!el)
		throw LowlevelError("No compiler configuration tag found");

	const List &list(el->getChildren());
	List::const_iterator iter;

	for(iter = list.begin(); iter != list.end(); iter++)
	{
		const string &elname((*iter)->getName());
		if(elname == "stackpointer")
			sp_name = (*iter)->getAttributeValue("register");
		else if(elname == "default_proto")
			parseDefaultProto(*iter, arg_names, ret_names);
	}
}

static std::unordered_map<std::string, std::string> parseRegisterData(const Element *el)
{
	const List &child_list(el->getChildren());
	List::const_iterator iter;

	std::unordered_map<std::string, std::string> reg_group;

	for(iter = child_list.begin(); iter != child_list.end(); iter++)
	{
		if((*iter)->getName() != "register")
			throw LowlevelError("Unexpected node get from register_data in processor spec!");

		const std::string &name = (*iter)->getAttributeValue("name");
		std::string group, hidden, unused, rename;
		try
		{
			group = (*iter)->getAttributeValue("group");
			hidden = (*iter)->getAttributeValue("hidden");
			unused = (*iter)->getAttributeValue("unused");
			rename = (*iter)->getAttributeValue("rename");
		}
		catch(const DecoderError &e)
		{
			std::string err_prefix("Unknown attribute: ");
			if(e.explain == err_prefix + "group") { /* nothing */ }
			else if(e.explain == err_prefix + "hidden") { /* nothing */ }
			else if(e.explain == err_prefix + "unused") { /* nothing */ }
			else if(e.explain == err_prefix + "rename") { /* nothing */ }
			else
				throw;
		}

		reg_group.insert({name, group});
	}

	return reg_group;
}

/*
 * From architecture.cc's parseProcessorConfig()
 * This function is used to parse processor config.
 * It is stripped to only parse context_data.
 * Context data is used to fill contextreg.
 */
void SleighAsm::parseProcConfig(DocumentStorage &store)

{
	const Element *el = store.getTag("processor_spec");
	if(!el)
		throw LowlevelError("No processor configuration tag found");
	XmlDecode decoder(&trans, el);
	uint4 elemId = decoder.openElement(ELEM_PROCESSOR_SPEC);
	for(;;)
	{
		uint4 subId = decoder.peekElement();
		if(subId == 0)
			break;
		if (subId == ELEM_PROGRAMCOUNTER)
		{
			decoder.openElement();
			pc_name = decoder.readString(ATTRIB_REGISTER);
			decoder.closeElement(subId);
		}
		else if (subId == ELEM_CONTEXT_DATA)
			context.decodeFromSpec(decoder);
		else if (subId == ELEM_REGISTER_DATA)
		{
			decoder.openElement();
			parseRegisterData(decoder.getCurrentXmlElement());
			decoder.closeElement(subId);
		}
		else
		{
			decoder.openElement();
			decoder.closeElementSkipping(subId);
		}
	}
	decoder.closeElement(elemId);
}

/*
 * From sleigh_arch.cc's buildSpecFile()
 * This function is used to fill DocumentStorage with sleigh files.
 */
void SleighAsm::buildSpecfile(DocumentStorage &store)
{
	const LanguageDescription &language(description[languageindex]);
	std::string compiler = sleigh_id.substr(sleigh_id.rfind(':') + 1);
	const CompilerTag &compilertag(language.getCompiler(compiler));

	std::string processorfile;
	std::string compilerfile;
	std::string slafile;

	specpaths.findFile(processorfile, language.getProcessorSpec());
	specpaths.findFile(compilerfile, compilertag.getSpec());
	specpaths.findFile(slafile, language.getSlaFile());

	try
	{
		Document *doc = store.openDocument(processorfile);
		store.registerTag(doc->getRoot());
	}
	catch(DecoderError &err)
	{
		ostringstream serr;
		serr << "XML error parsing processor specification: " << processorfile;
		serr << "\n " << err.explain;
		throw SleighError(serr.str());
	}
	catch(LowlevelError &err)
	{
		ostringstream serr;
		serr << "Error reading processor specification: " << processorfile;
		serr << "\n " << err.explain;
		throw SleighError(serr.str());
	}

	try
	{
		Document *doc = store.openDocument(compilerfile);
		store.registerTag(doc->getRoot());
	}
	catch(DecoderError &err)
	{
		ostringstream serr;
		serr << "XML error parsing compiler specification: " << compilerfile;
		serr << "\n " << err.explain;
		throw SleighError(serr.str());
	}
	catch(LowlevelError &err)
	{
		ostringstream serr;
		serr << "Error reading compiler specification: " << compilerfile;
		serr << "\n " << err.explain;
		throw SleighError(serr.str());
	}

	try
	{
		Document *doc = store.openDocument(slafile);
		store.registerTag(doc->getRoot());
	}
	catch(DecoderError &err)
	{
		ostringstream serr;
		serr << "XML error parsing SLEIGH file: " << slafile;
		serr << "\n " << err.explain;
		throw SleighError(serr.str());
	}
	catch(LowlevelError &err)
	{
		ostringstream serr;
		serr << "Error reading SLEIGH file: " << slafile;
		serr << "\n " << err.explain;
		throw SleighError(serr.str());
	}
}

/*
 * From sleigh_arch.cc's resolveArchitecture()
 * This function is used to resolve the index of asm.cpu in description.
 * It is stripped because asm.cpu is the result of normalizeArchitecture().
 */
void SleighAsm::resolveArch(const string &archid)
{
	std::string baseid = archid.substr(0, archid.rfind(':'));
	languageindex = -1;
	for(size_t i = 0; i < description.size(); i++)
	{
		std::string id = description[i].getId();
		if(id == archid || id == baseid)
		{
			languageindex = i;
			if(description[i].isDeprecated())
				throw LowlevelError("Language " + baseid + " is deprecated");
			break;
		}
	}

	if(languageindex == -1)
		throw LowlevelError("No sleigh specification for " + baseid);
}

/*
 * From sleigh_arch.cc's scanForSleighDirectories()
 * This function is used to scan directories for SLEIGH specification files.
 */
void SleighAsm::scanSleigh(const string &rootpath)
{
	specpaths = FileManage(); // Empty specpaths

	std::vector<std::string> ghidradir;
	std::vector<std::string> procdir;
	std::vector<std::string> procdir2;
	std::vector<std::string> languagesubdirs;

	FileManage::scanDirectoryRecursive(ghidradir, "Ghidra", rootpath, 2);
	for(size_t i = 0; i < ghidradir.size(); ++i)
	{
		FileManage::scanDirectoryRecursive(procdir, "Processors", ghidradir[i],
		                                   1); // Look for Processors structure
		FileManage::scanDirectoryRecursive(procdir, "contrib", ghidradir[i], 1);
	}
	if(procdir.size() != 0)
	{
		for(size_t i = 0; i < procdir.size(); ++i)
			FileManage::directoryList(procdir2, procdir[i]);

		vector<string> datadirs;
		for(size_t i = 0; i < procdir2.size(); ++i)
			FileManage::scanDirectoryRecursive(datadirs, "data", procdir2[i], 1);

		vector<string> languagedirs;
		for(size_t i = 0; i < datadirs.size(); ++i)
			FileManage::scanDirectoryRecursive(languagedirs, "languages", datadirs[i], 1);

		for(size_t i = 0; i < languagedirs.size(); ++i)
			languagesubdirs.push_back(languagedirs[i]);

		// In the old version we have to go down one more level to get to the ldefs
		for(size_t i = 0; i < languagedirs.size(); ++i)
			FileManage::directoryList(languagesubdirs, languagedirs[i]);
	}
	// If we haven't matched this directory structure, just use the rootpath as the directory
	// containing the ldef
	if(languagesubdirs.size() == 0)
		languagesubdirs.push_back(rootpath);

	for(size_t i = 0; i < languagesubdirs.size(); ++i)
		specpaths.addDir2Path(languagesubdirs[i]);
}

/*
 * From sleigh_arch.cc's loadLanguageDescription()
 * This function is used to read a SLEIGH .ldefs file.
 */
void SleighAsm::loadLanguageDescription(const string &specfile)
{
	ifstream s(specfile.c_str());
	if(!s)
		throw LowlevelError("Unable to open: " + specfile);

	XmlDecode decoder((const AddrSpaceManager *)0);
	try
	{
		decoder.ingestStream(s);
	}
	catch(DecoderError &err)
	{
		throw LowlevelError("Unable to parse sleigh specfile: " + specfile);
	}

	uint4 elemId = decoder.openElement(ELEM_LANGUAGE_DEFINITIONS);
	for(;;) {
		uint4 subId = decoder.peekElement();
		if(subId == 0)
			break;
		if(subId == ELEM_LANGUAGE)
		{
			description.emplace_back();
			description.back().decode(decoder);
		}
		else
		{
			decoder.openElement();
			decoder.closeElementSkipping(subId);
		}
	}
	decoder.closeElement(elemId);
}

/*
 * From sleigh_arch.cc's collectSpecFiles()
 * This function is used to collect all .ldefs files.
 */
void SleighAsm::collectSpecfiles(void)
{
	if(!description.empty())
		return;

	std::vector<std::string> testspecs;
	std::vector<std::string>::iterator iter;
	specpaths.matchList(testspecs, ".ldefs", true);
	for(iter = testspecs.begin(); iter != testspecs.end(); iter++)
		loadLanguageDescription(*iter);
}

RzConfig *SleighAsm::getConfig(RzAsm *a)
{
	RzCore *core = a->num ? (RzCore *)(a->num->userptr) : NULL;
	if(!core)
		return nullptr;
	return core->config;
}

RzConfig *SleighAsm::getConfig(RzAnalysis *a)
{
	RzCore *core = a ? (RzCore *)a->coreb.core : nullptr;
	if(!core)
		return nullptr;
	return core->config;
}

std::string SleighAsm::getSleighHome(RzConfig *cfg)
{
	const char varname[] = "ghidra.sleighhome";
	const char *path = nullptr;

	// user-set, for example from .rizinrc
	if(cfg && rz_config_node_get(cfg, varname))
	{
		path = rz_config_get(cfg, varname);
		if(path && *path)
			return path;
	}

	// SLEIGHHOME env
	path = getenv("SLEIGHHOME");
	if(path && *path)
	{
		if(cfg)
			rz_config_set(cfg, varname, path);
		return path;
	}

#ifdef RZ_GHIDRA_SLEIGHHOME_DEFAULT
	if(rz_file_is_directory(RZ_GHIDRA_SLEIGHHOME_DEFAULT))
	{
		if(cfg)
			rz_config_set(cfg, varname, RZ_GHIDRA_SLEIGHHOME_DEFAULT);
		return RZ_GHIDRA_SLEIGHHOME_DEFAULT;
	}
#endif

	path = rz_str_home(".local/share/rizin/rz-pm/git/ghidra");
	if(rz_file_is_directory(path))
	{
		if(cfg)
			rz_config_set(cfg, varname, path);
		std::string res(path);
		rz_mem_free((void *)path);
		return res;
	}
	else
		throw LowlevelError("No Sleigh Home found!");
}

int SleighAsm::disassemble(RzAsmOp *op, ut64 offset, const ut8 *buf, size_t size)
{
	resetBuffer(offset, buf, size);
	AssemblySlg assem(this);
	Address addr(trans.getDefaultCodeSpace(), offset);
	int length = 0;
	try
	{
		length = trans.printAssembly(assem, addr);
		rz_strbuf_set(&op->buf_asm, assem.str);
		/*
		auto *ins = trans.getInstruction(addr);
		stringstream ss;
		ss << assem.str << " " << ins->printFlowType(ins->getFlowType());
		for(auto p: ins->getFlows())
		    ss << " " << p;
		rz_strbuf_set(&op->buf_asm, ss.str().c_str());
		*/
	}
	catch(BadDataError &err)
	{
		/* Meet unknown data -> invalid opcode */
		rz_strbuf_set(&op->buf_asm, "invalid");
		length = alignment;
	}
	catch(UnimplError &err)
	{
		/* Meet unimplemented data -> invalid opcode */
		rz_strbuf_set(&op->buf_asm, "invalid");
		length = alignment;
	}
	return length;
}

int SleighAsm::genOpcode(PcodeSlg &pcode_slg, Address &addr, const ut8 *buf, size_t size)
{
	resetBuffer(addr.getOffset(), buf, size);
	int length = 0;
	try
	{
		length = trans.oneInstruction(pcode_slg, addr);
	}
	catch(BadDataError &err)
	{
		/* Meet unknown data -> invalid opcode */
		length = -1;
	}
	catch(UnimplError &err)
	{
		/* Meet unimplemented data -> invalid opcode */
		length = -1;
	}
	return length;
}

void SleighAsm::initRegMapping(void)
{
	reg_mapping.clear();
	std::map<VarnodeData, std::string> reglist;
	std::set<std::string> S;
	trans.getAllRegisters(reglist);

	for(auto iter = reglist.cbegin(); iter != reglist.cend(); ++iter)
	{
		std::string tmp;
		for(auto p = iter->second.cbegin(); p != iter->second.cend(); ++p)
			tmp.push_back(std::tolower(*p));
		while(S.count(tmp))
			tmp += "_dup";
		S.insert(tmp);
		reg_mapping[iter->second] = tmp;
	}
}

std::vector<RizinReg> SleighAsm::getRegs(void)
{
	std::map<VarnodeData, std::string> reglist;
	std::vector<RizinReg> rizin_reglist;
	trans.getAllRegisters(reglist);

	size_t offset = 0, offset_last = reglist.begin()->first.size;
	size_t sleigh_offset = reglist.begin()->first.offset;
	size_t sleigh_last = reglist.begin()->first.size + sleigh_offset;

	for(auto p = reglist.begin(); p != reglist.end(); p++)
	{
		if(sleigh_last <= p->first.offset) // Assume reg's size must be > 0, but mips???
		{
			offset = offset_last;
			offset_last += p->first.size;
			sleigh_offset = p->first.offset;
			sleigh_last = sleigh_offset + p->first.size;
		}
		rizin_reglist.push_back(
		    RizinReg{p->second, p->first.size, p->first.offset - sleigh_offset + offset});
	}

	return rizin_reglist;
}

ostream &operator<<(ostream &s, const PcodeOperand &arg)
{
	switch(arg.type)
	{
		case PcodeOperand::REGISTER: s << arg.name; break;
		case PcodeOperand::UNIQUE: s << "unique(" << arg.offset << ", " << arg.size << ")"; break;
		// case PcodeOperand::RAM: s << "ram(" << arg.offset << ", " << arg.size << ")";
		case PcodeOperand::RAM: s << arg.offset; break;
		case PcodeOperand::CONST: s << arg.number; break;
		default: throw LowlevelError("Unexpected type of PcodeOperand found in operator<<.");
	}
	return s;
}

ostream &operator<<(ostream &s, const Pcodeop &op)
{
	if(op.output)
		s << *op.output << " = ";
	s << get_opname(op.type);
	if(op.input0)
		s << " " << *op.input0;
	if(op.input1)
		s << " " << *op.input1;
	return s;
}

void AssemblySlg::dump(const Address &addr, const string &mnem, const string &body)
{
	std::string res;
	for(ut64 i = 0; i < body.size();)
	{
		std::string tmp;
		while(i < body.size() && !std::isalnum(body[i]))
			res.push_back(body[i++]);
		while(i < body.size() && std::isalnum(body[i]))
			tmp.push_back(body[i++]);
		if(sasm->reg_mapping.find(tmp) != sasm->reg_mapping.end())
			res += sasm->reg_mapping[tmp];
		else
			res += tmp;
	}
	if(res.empty())
		str = rz_str_newf("%s", mnem.c_str());
	else
		str = rz_str_newf("%s %s", mnem.c_str(), res.c_str());
}

PcodeOperand *PcodeSlg::parse_vardata(VarnodeData &data)
{
	AddrSpace *space = data.space;
	PcodeOperand *operand = nullptr;
	if(space->getName() == "register" || space->getName() == "mem")
	{
		operand = new PcodeOperand(sanalysis->reg_mapping[space->getTrans()->getRegisterName(
		                               data.space, data.offset, data.size)],
		                           data.size);
		operand->type = PcodeOperand::REGISTER;
	}
	else if(space->getName() == "ram" || space->getName() == "DATA" || space->getName() == "code")
	{
		operand = new PcodeOperand(data.offset, data.size);
		operand->type = PcodeOperand::RAM;
	}
	else if(space->getName() == "const")
	{
		// space.cc's ConstantSpace::printRaw()
		operand = new PcodeOperand(data.offset);
		operand->type = PcodeOperand::CONST;
		operand->size = data.size; // To aviod ctor's signature collide with RAM's
	}
	else if(space->getName() == "unique")
	{
		operand = new PcodeOperand(data.offset, data.size);
		operand->type = PcodeOperand::UNIQUE;
	}
	else
		throw LowlevelError("Unsupported AddrSpace type appear.");
	return operand;
}

void SleighAsm::resetBuffer(ut64 offset, const ut8 *buf, size_t size)
{
	loader.resetBuffer(offset, buf, size);
	// To refresh cache when file content is modified.
	ParserContext *ctx = trans.getContext(Address(trans.getDefaultCodeSpace(), offset), ParserContext::uninitialized);
	if(ctx->getParserState() > ParserContext::uninitialized)
	{
		ut8 *cached = ctx->getBuffer();
		size_t i = 0;
		for(; i < size && cached[i] == buf[i]; ++i) {}
		if(i != size)
			ctx->setParserState(ParserContext::uninitialized);
	}
}
