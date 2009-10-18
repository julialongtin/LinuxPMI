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

	echo "*** Deleting old initrds"
	rm initrd*

	echo "*** Creating new initrd file"
	dd if=/dev/zero of=initrd bs=1024 count=32000 1> /dev/null

	echo "*** Formating ext2"
	/sbin/mkfs.ext2 -F -m 0 -b 1024 initrd 1> /dev/null

	echo "*** Creating mountpoint"
	rm -rf mountpoint 
	mkdir mountpoint

	echo "*** Loopback mounting initrd"
	mount -o loop initrd mountpoint/
	cd mountpoint

	echo "*** Making directories in our new /"
	mkdir -p bin etc sbin lib${LIBDIRSUFFIX} proc \
	sys tmp usr/bin var/lock var/log dev \
	usr/sbin
	cp -a /sbin/ldconfig sbin/
	cp -a /bin/bash /bin/which bin/
	cp -a /usr/bin/mktemp usr/bin/
	cd ${OURPWD}
}

finishinitrd() {
	echo "*** Copying etc files"
	cp -a files/etc/* mountpoint/etc/
	echo "*** Copying device files"
	cp -a files/dev/* mountpoint/dev/
	cp -a /dev/console /dev/kmem /dev/mem /dev/null /dev/ram0 \
	/dev/tty1 /dev/tty2 /dev/tty5 mountpoint/dev/

	cd mountpoint
	echo "*** Chowning all files to root"
	chown -R root:root *
	cd ${OURPWD}

#	find . | cpio --quiet -c -o | gzip > ../initrd.img
	echo "*** umounting initrd"
#	cd ${OURPWD}
	umount mountpoint
	#initrd magics?
	echo "*** gzipping initrd"
	gzip -9 initrd
}

busybox() {
	echo "*** Copying busybox config file"
	cp bbconfig busybox-${BUSYBOXVERSION}/.config
	#build busybox
	echo "*** Building busybox, may take some time, up to 5 minutes"
	cd busybox-${BUSYBOXVERSION}
#	make clean 1> /dev/null
	make 1> /dev/null
	#copy to staging area

	echo "*** Installing busybox + symlinks"
	make CONFIG_PREFIX=${OURPWD}/mountpoint/ install 1> /dev/null
	cd ${OURPWD}
	echo "*** Setuid root busybox"
	chmod u+s mountpoint/bin/busybox
}

libs() {
	#ldd the binaries?
	echo "*** Getting ldd of binaries"
	lddlibs=`ldd mountpoint/bin/bash | grep -oE /lib[A-Za-z0-9./\-]+` 
	#copy libraries to staging area
	echo "*** Copying libraries to initrd"
	for each in $lddlibs; do {
		cp $each mountpoint/lib${LIBDIRSUFFIX}
	} done;
	
}

migtort() { 
	echo "*** Building migtorture"
	#build migtorture
	cd ${GITROOT}/2.6/tools/migtorture

#	make clean 1> /dev/null
	make 1> /dev/null
	#copy to staging area
	echo "*** Copying migtorture to initrd"
	
	files=`find . | xargs file | grep "executable" | cut -f 1 -d :`
	for each in $files; do {
		cp -a $each ${OURPWD}/mountpoint/usr/bin
	} done;
	cd ${OURPWD}
}

setupinitrd
migtort
busybox
libs
finishinitrd



