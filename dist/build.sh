#!/bin/sh
[ -z "${VERSION}" ] && VERSION=3.9.0
RV=${VERSION}
RA=amd64
(
	echo "[*] Downloading r2-${RV}-${RA}"
	if [ ! -f radare2_${RV}_${RA}.deb ]; then
		wget -c http://radare.mikelloc.com/get/${RV}/radare2_${RV}_${RA}.deb
	fi
	if [ ! -f radare2-dev_${RV}_${RA}.deb ]; then
		wget -c http://radare.mikelloc.com/get/${RV}/radare2-dev_${RV}_${RA}.deb
	fi
	echo "[*] Installing r2-${RV}-${RA}"
	sudo dpkg -i radare2_${RV}_${RA}.deb
	sudo dpkg -i radare2-dev_${RV}_${RA}.deb
)

export PATH=/tmp/node-${NV}-${NA}/bin:$PATH
[ -z "${DESTDIR}" ] && DESTDIR=/
[ -z "${R2_LIBR_PLUGINS}" ] && R2_LIBR_PLUGINS=/usr/lib/radare2/last
make R2_PLUGDIR=${R2_LIBR_PLUGINS} DESTDIR=${DESTDIR}
