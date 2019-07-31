
#ifndef R2GHIDRA_R2EMIT_H
#define R2GHIDRA_R2EMIT_H

#include "prettyprint.hh"
#include "address.hh"

class R2Emit : public EmitPrettyPrint
{
	private:
	vector<vector<Address>> offsets;
	vector<Address> line;
	public:
	R2Emit(int4 mls);
	void tagLine(void);
	void tagLine(int4 indent);
	void resetOffsetLine(void);
	int4 startIndent(void);
	void pushOffset(Address off);
	void overflow(void);
	vector<vector<Address>> getOffsets();
};

#endif
