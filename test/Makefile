
USE_JAVASHIT:=1
ifeq ($(USE_JAVASHIT),1)
	RUN=run_js
else
	RUN=run_v
endif

all: $(RUN)

node_modules:
	npm install

.PHONY: install_js
install_js: node_modules

.PHONY: run_js
run_js: node_modules r2-testbins
	npx r2r db/extras

# TODO: i should use r2r.v when ready
.PHONY: i
i: node_modules r2-testbins
	npx r2r -i db/extras

.PHONY: run_v
run_v:
	r2r -d db extras

r2-testbins:
	git clone https://github.com/radareorg/radare2-testbins --depth 1 r2-testbins
