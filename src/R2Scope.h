/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_R2SCOPE_H
#define R2GHIDRA_R2SCOPE_H

#include <database.hh>

#include <r_types.h>

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

class R2Architecture;
typedef struct r_anal_function_t RAnalFunction;
typedef struct r_flag_item_t RFlagItem;

class R2Scope : public Scope
{
	private:
		R2Architecture *arch;
		ScopeInternal *cache;

		FunctionSymbol *registerFunction(RAnalFunction *fcn) const;
		Symbol *registerFlag(RFlagItem *flag) const;
		Symbol *queryR2Absolute(ut64 addr, bool contain) const;
		Symbol *queryR2(const Address &addr, bool contain) const;
		LabSymbol *queryR2FunctionLabel(const Address &addr) const;

	protected:
		// TODO? void addRange(AddrSpace *spc,uintb first,uintb last) override;
		void removeRange(AddrSpace *spc,uintb first,uintb last) override				{ throw LowlevelError("remove_range should not be performed on radare2 scope"); }
		void addSymbolInternal(Symbol *sym) override									{ throw LowlevelError("addSymbolInternal unimplemented"); }
		SymbolEntry *addMapInternal(Symbol *sym, uint4 exfl, const Address &addr, int4 off, int4 sz, const RangeList &uselim) override { throw LowlevelError("addMapInternal unimplemented"); }
		SymbolEntry *addDynamicMapInternal(Symbol *sym, uint4 exfl, uint8 hash, int4 off, int4 sz, const RangeList &uselim) override { throw LowlevelError("addMap unimplemented"); }

	public:
		explicit R2Scope(R2Architecture *arch);
		~R2Scope() override;

		Scope *buildSubScope(const string &nm) override;
		void clear(void) override										{ cache->clear(); }
		SymbolEntry *addSymbol(const string &name, Datatype *ct, const Address &addr, const Address &usepoint) override	{ return cache->addSymbol(name, ct, addr, usepoint); }
		string buildVariableName(const Address &addr, const Address &pc, Datatype *ct,int4 &index,uint4 flags) const override { return cache->buildVariableName(addr,pc,ct,index,flags); }
		string buildUndefinedName(void) const override					{ return cache->buildUndefinedName(); }
		void setAttribute(Symbol *sym,uint4 attr) override				{ cache->setAttribute(sym,attr); }
		void clearAttribute(Symbol *sym,uint4 attr) override			{ cache->clearAttribute(sym,attr); }
		void setDisplayFormat(Symbol *sym,uint4 attr) override			{ cache->setDisplayFormat(sym,attr); }

		SymbolEntry *findAddr(const Address &addr,const Address &usepoint) const override;
		SymbolEntry *findContainer(const Address &addr,int4 size, const Address &usepoint) const override;
		 SymbolEntry *findClosestFit(const Address &addr,int4 size, const Address &usepoint) const { throw LowlevelError("findClosestFit unimplemented"); }
		Funcdata *findFunction(const Address &addr) const;
		ExternRefSymbol *findExternalRef(const Address &addr) const;
		LabSymbol *findCodeLabel(const Address &addr) const;
		bool isNameUsed(const string &name, const Scope *op2) const override { throw LowlevelError("isNameUsed unimplemented"); }
		Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const;

		SymbolEntry *findOverlap(const Address &addr,int4 size) const	{ throw LowlevelError("findOverlap unimplemented"); }
		SymbolEntry *findBefore(const Address &addr) const				{ throw LowlevelError("findBefore unimplemented"); }
		SymbolEntry *findAfter(const Address &addr) const				{ throw LowlevelError("findAfter unimplemented"); }
		void findByName(const string &name,vector<Symbol *> &res) const	{ throw LowlevelError("findByName unimplemented"); }
		MapIterator begin() const override								{ throw LowlevelError("begin unimplemented"); }
		MapIterator end() const override								{ throw LowlevelError("end unimplemented"); }
		list<SymbolEntry>::const_iterator beginDynamic() const override	{ throw LowlevelError("beginDynamic unimplemented"); }
		list<SymbolEntry>::const_iterator endDynamic() const override	{ throw LowlevelError("endDynamic unimplemented"); }
		list<SymbolEntry>::iterator beginDynamic() override				{ throw LowlevelError("beginDynamic unimplemented"); }
		list<SymbolEntry>::iterator endDynamic() override				{ throw LowlevelError("endDynamic unimplemented"); }
		void clearCategory(int4 cat) override							{ throw LowlevelError("clearCategory unimplemented"); }
		void clearUnlockedCategory(int4 cat) override					{ throw LowlevelError("clearUnlockedCategory unimplemented"); }
		void clearUnlocked() override									{ throw LowlevelError("clearUnlocked unimplemented"); }
		void restrictScope(Funcdata *f) override						{ throw LowlevelError("restrictScope unimplemented"); }
		void removeSymbolMappings(Symbol *symbol) override				{ throw LowlevelError("removeSymbolMappings unimplemented"); }
		void removeSymbol(Symbol *symbol) override						{ throw LowlevelError("removeSymbol unimplemented"); }
		void renameSymbol(Symbol *sym,const string &newname) override	{ throw LowlevelError("renameSymbol unimplemented"); }
		void retypeSymbol(Symbol *sym,Datatype *ct) override			{ throw LowlevelError("retypeSymbol unimplemented"); }
		string makeNameUnique(const string &nm) const override			{ throw LowlevelError("makeNameUnique unimplemented"); }
		void saveXml(ostream &s) const override							{ cache->saveXml(s); }
		void restoreXml(const Element *el) override						{ throw LowlevelError("restoreXml unimplemented"); }
		void printEntries(ostream &s) const override					{ throw LowlevelError("printEntries unimplemented"); }
		int4 getCategorySize(int4 cat) const override					{ throw LowlevelError("getCategorySize unimplemented"); }
		Symbol *getCategorySymbol(int4 cat,int4 ind) const override		{ throw LowlevelError("getCategorySymbol unimplemented"); }
		void setCategory(Symbol *sym,int4 cat,int4 ind) override		{ throw LowlevelError("setCategory unimplemented"); }
};

#endif //R2GHIDRA_R2SCOPE_H
