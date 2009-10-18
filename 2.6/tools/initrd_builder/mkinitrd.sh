#!/bin/bash

BUSYBOXVERSION=1.15.2
GITROOT=/array/linuxpmi/linuxPMI
OURPWD=${GITROOT}/2.6/tools/initrd_builder

ARCH=${ARCH:-i386}

if [ "$ARCH" = "i486" ]; then
  LIBDIRSUFFIX=
elif [ "$ARCH" = "i686" ]; then
  LIBDIRSUFFIX=
elif [ "$ARCH" = "x86_64" ]; then
  LIBDIRSUFFIX=64
fi

set -e

setupinitrd() {
	#umount mountpoint

	rm initrd*
	dd if=/dev/zero of=initrd bs=1024 count=40000
	/sbin/mkfs.ext2 -F -m 0 -b 1024 initrd
	rm -rf mountpoint 
	mkdir mountpoint
	mount -o loop initrd mountpoint/
	cd mountpoint
	mkdir -p bin etc sbin lib${LIBDIRSUFFIX} proc \
	sys tmp migtorture usr/bin var/lock var/log dev \
	usr/sbin
	cd ${OURPWD}
}

finishinitrd() {
	cd mountpoint
	chown -R root:root *
	cd ${OURPWD}
	umount mountpoint
	#initrd magics?
	gzip initrd
}

busybox() {
	#copy config file
	cp bbconfig busybox-${BUSYBOXVERSION}/.config
	#build busybox
	cd busybox-${BUSYBOXVERSION}
	make
	#copy to staging area
	make CONFIG_PREFIX=${OURPWD}/mountpoint/ install
	#setuid root busybox
	cd ${OURPWD}
	chmod u+s mountpoint/bin/busybox
}

libs() {
	#ldd the binaries?
	lddlibs=`ldd mountpoint/migtorture/eatcpu | grep -oE /lib[A-Za-z0-9./\-]+` 
	#copy libraries to staging area
	for each in $lddlibs; do {
		cp $each mountpoint/lib${LIBDIRSUFFIX}
	} done;
	
}

#scripts() {
#	#copy scripts from git to staging area
#}

migtort() { 
	#build migtorture
	cd ${GITROOT}/2.6/tools/migtorture
	make
	#copy to staging area
	cp -a . ${OURPWD}/mountpoint/migtorture
	cd ${OURPWD}
}

setupinitrd
migtort
busybox
libs
finishinitrd



