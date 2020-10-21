include ./CONFIG

DEPENDS=
CROSSARCH=x64
PWD=$(shell pwd)
PACKAGE_DIR?=${PWD}

DOCKCROSS=$(PWD)/../dockcross
R2PLUGDIR=/usr/lib/radare2/$(VERSION)

all: root
	sudo rm -rf control data
	${MAKE} clean
	mkdir -p data
	cp -rf root/* data
	${MAKE} control
	${MAKE} deb

root:
	cd ../.. && $(DOCKCROSS) --image dockcross/linux-$(CROSSARCH) \
	bash -c 'sh dist/build.sh\
		; rm -rf build \
		&& mkdir -p build \
		&& cd build \
		&& cmake .. \
			-DRADARE2_INSTALL_PLUGDIR=$(shell r2 -HR2_LIBR_PLUGINS) \
			-DCMAKE_INSTALL_PREFIX=$(shell r2 -HR2_PREFIX) \
		&& make -j4 \
		&& make install DESTDIR=/work/dist/debian/root'

purge: clean
	rm -rf root

summary:
	echo $(VERSION)

include deb.mk
