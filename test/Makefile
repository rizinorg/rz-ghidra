
all: run

node_modules:
	npm install

.PHONY: install
install: node_modules

.PHONY: run
run: node_modules r2-testbins
	npx r2r db/extras

.PHONY: i
i: node_modules r2-testbins
	npx r2r -i db/extras

r2-testbins:
	git clone https://github.com/radareorg/radare2-testbins --depth 1 r2-testbins
