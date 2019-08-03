
#ifndef R2GHIDRA_R2EMIT_H
#define R2GHIDRA_R2EMIT_H

#include <prettyprint.hh>
#include <address.hh>

class R2Emit : public EmitPrettyPrint
{
	private:
		vector<vector<Address>> offsets;
		vector<Address> line;

	public:
		explicit R2Emit(int4 mls);
		void tagLine() override;
		void tagLine(int4 indent) override ;
		void resetOffsetLine();
		void pushOffset(Address off);
		vector<vector<Address>> getOffsets();
};

#endif
