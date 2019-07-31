
#include "R2Emit.h"

R2Emit::R2Emit(int4 mls) : EmitPrettyPrint(mls)
{
}

void R2Emit::tagLine(void)
{
	resetOffsetLine();
	EmitPrettyPrint::tagLine();
}

void R2Emit::tagLine(int4 indent)
{
	resetOffsetLine();
	EmitPrettyPrint::tagLine(indent);
}

int4 R2Emit::startIndent(void)
{
	/* resetOffsetLine(); */
	return EmitPrettyPrint::startIndent();
}

void R2Emit::overflow(void)
{
	EmitPrettyPrint::overflow();
	resetOffsetLine();
}

void R2Emit::resetOffsetLine()
{
	vector<Address> lc(line);
	offsets.push_back(vector<Address>(lc));
	line.clear();
}

void R2Emit::pushOffset(Address off)
{
	line.push_back(off);
}

vector<vector<Address>> R2Emit::getOffsets()
{
	return offsets;
}

