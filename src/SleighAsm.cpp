/* radare - LGPL - Copyright 2020 - FXTi */

#include "SleighAsm.h"

void SleighAsm::init(const char *id, RIO *io, RConfig *cfg)
{
	if(!io)
		throw LowlevelError("Can't get RIO from RBin");

	if(description.empty())
	{
		/* Initialize sleigh spec files */
		scanSleigh(getSleighHome(cfg));
		collectSpecfiles();
	}

	if(!sleigh_id.empty() && sleigh_id == id)
		return;

	initInner(io, id);
}

void SleighAsm::initInner(RIO *io, const char *cpu)
{
	/* Initialize Sleigh */
	loader = std::move(AsmLoadImage(io));
	docstorage = std::move(DocumentStorage());
	resolveArch(cpu);
	buildSpecfile(docstorage);
	context = std::move(ContextInternal());
	trans.reset(&loader, &context);
	trans.initialize(docstorage);
	parseProcConfig(docstorage);
	parseCompConfig(docstorage);
	alignment = trans.getAlignment();
	trans.clearCache();
	initRegMapping();

	sleigh_id = cpu;
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
		catch(const XmlError &e)
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

	const List &list(el->getChildren());
	List::const_iterator iter;

	for(iter = list.begin(); iter != list.end(); iter++)
	{
		const string &elname((*iter)->getName());
		if(elname == "context_data")
			context.restoreFromSpec(*iter, &trans);

		if(elname == "programcounter")
			pc_name = (*iter)->getAttributeValue("register");

		if(elname == "register_data")
			reg_group = parseRegisterData(*iter);
	}
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
	catch(XmlError &err)
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
	catch(XmlError &err)
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
	catch(XmlError &err)
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
 * This function is used to reolve the index of asm.cpu in description.
 * It is stripped because asm.cpu is the result of normalizeArchitecture().
 */
void SleighAsm::resolveArch(const string &archid)
{
	std::string baseid = archid.substr(0, archid.rfind(':'));
	languageindex = -1;
	for(size_t i = 0; i < description.size(); i++)
	{
		if(description[i].getId() == baseid)
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

	Document *doc;
	Element *el;
	try
	{
		doc = xml_tree(s);
	}
	catch(XmlError &err)
	{
		throw LowlevelError("Unable to parse sleigh specfile: " + specfile);
	}

	el = doc->getRoot();
	const List &list(el->getChildren());
	List::const_iterator iter;
	for(iter = list.begin(); iter != list.end(); ++iter)
	{
		if((*iter)->getName() != "language")
			continue;
		description.push_back(LanguageDescription());
		description.back().restoreXml(*iter);
	}
	delete doc;
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

RConfig *SleighAsm::getConfig(RAsm *a)
{
	RCore *core = a->num ? (RCore *)(a->num->userptr) : NULL;
	if(!core)
		throw LowlevelError("Can't get RCore from RAsm's RNum");
	return core->config;
}

RConfig *SleighAsm::getConfig(RAnal *a)
{
	RCore *core = a ? (RCore *)a->coreb.core : nullptr;
	if(!core)
		throw LowlevelError("Can't get RCore from RAnal's RCoreBind");
	return core->config;
}

std::string SleighAsm::getSleighHome(RConfig *cfg)
{
	if(!cfg)
		throw LowlevelError("SleighAsm::get_sleigh_home: cfg is nullptr.");
	const char varname[] = "r2ghidra.sleighhome";
	const char *path = nullptr;

	// user-set, for example from .radare2rc
	if(r_config_node_get(cfg, varname))
	{
		path = r_config_get(cfg, varname);
		if(path && *path)
			return path;
	}

	// SLEIGHHOME env
	path = getenv("SLEIGHHOME");
	if(path && *path)
	{
		r_config_set(cfg, varname, path);
		return path;
	}

#ifdef R2GHIDRA_SLEIGHHOME_DEFAULT
	if(r_file_is_directory(R2GHIDRA_SLEIGHHOME_DEFAULT))
	{
		r_config_set(cfg, varname, R2GHIDRA_SLEIGHHOME_DEFAULT);
		return R2GHIDRA_SLEIGHHOME_DEFAULT;
	}
#endif

	path = r_str_home(".local/share/radare2/r2pm/git/ghidra");
	if(r_file_is_directory(path))
	{
		r_config_set(cfg, varname, path);
		std::string res(path);
		r_mem_free((void *)path);
		return res;
	}
	else
		throw LowlevelError("No Sleigh Home found!");
}

int SleighAsm::disassemble(RAsmOp *op, unsigned long long offset)
{
	AssemblySlg assem(this);
	Address addr(trans.getDefaultCodeSpace(), offset);
	int length = 0;
	try
	{
		//PcodeEmitDummy tmp;
		//length = trans.oneInstruction(tmp, addr); // To refresh ins cache.
		length = trans.printAssembly(assem, addr);
		r_strbuf_set(&op->buf_asm, assem.str);
		/*
		auto *ins = trans.getInstruction(addr);
		stringstream ss;
		ss << assem.str << " " << ins->printFlowType(ins->getFlowType());
		for(auto p: ins->getFlows())
		    ss << " " << p;
		r_strbuf_set(&op->buf_asm, ss.str().c_str());
		*/
	}
	catch(BadDataError &err)
	{
		/* Meet unknown data -> invalid opcode */
		r_strbuf_set(&op->buf_asm, "invalid");
		length = alignment;
	}
	catch(UnimplError &err)
	{
		/* Meet unimplemented data -> invalid opcode */
		r_strbuf_set(&op->buf_asm, "invalid");
		length = alignment;
	}
	return length;
}

int SleighAsm::genOpcode(PcodeSlg &pcode_slg, Address &addr)
{
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

std::vector<R2Reg> SleighAsm::getRegs(void)
{
	std::map<VarnodeData, std::string> reglist;
	std::vector<R2Reg> r2_reglist;
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
		r2_reglist.push_back(
		    R2Reg{p->second, p->first.size, p->first.offset - sleigh_offset + offset});
	}

	return r2_reglist;
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
		while(!std::isalnum(body[i]))
			res.push_back(body[i++]);
		while(std::isalnum(body[i]))
			tmp.push_back(body[i++]);
		if(sasm->reg_mapping.find(tmp) != sasm->reg_mapping.end())
			res += sasm->reg_mapping[tmp];
		else
			res += tmp;
	}
	str = r_str_newf("%s %s", mnem.c_str(), res.c_str());
}

PcodeOperand *PcodeSlg::parse_vardata(VarnodeData &data)
{
	AddrSpace *space = data.space;
	PcodeOperand *operand = nullptr;
	if(space->getName() == "register" || space->getName() == "mem")
	{
		operand = new PcodeOperand(sanal->reg_mapping[space->getTrans()->getRegisterName(
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