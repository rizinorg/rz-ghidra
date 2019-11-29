
all: run

node_modules:
	npm install

.PHONY: install
install: node_modules

.PHONY: run
run: node_modules r2r
	npx r2r db/extras

.PHONY: i
i: node_modules r2r
	npx r2r -i db/extras

r2r:
	git clone https://github.com/radareorg/radare2-regressions --depth 1 r2r
