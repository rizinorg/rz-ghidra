
all: run

.PHONY: run
run: rizin-testbins
	rz-test -L db/extras

.PHONY: i
i: rizin-testbins
	rz-test -i db/extras

rizin-testbins:
	git clone https://github.com/rizinorg/rizin-testbins --depth 1 rizin-testbins
