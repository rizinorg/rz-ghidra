
all: run

.PHONY: run
run: r2-testbins
	r2r -L db/extras

.PHONY: i
i: r2-testbins
	r2r -i db/extras

r2-testbins:
	git clone https://github.com/radareorg/radare2-testbins --depth 1 r2-testbins
