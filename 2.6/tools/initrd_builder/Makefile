
BUSYBOXVERSION="1.15.2"
GITROOT="/array/linuxpmi/linuxPMI"
PWD="`pwd`"

initrd : busybox libs scripts migtorture staging
	#build .img file from staging area
	#  dd a file
	rm initrd
	dd if=/dev/zero of=initrd bs=1024 count=20000

	#  mkfs ext2
	/sbin/mkfs.ext2 -F initrd
	#  loopback mount
	rm -rf mountpoint
	mkdir mountpoint
	mount -o loop initrd mountpoint/  
	#  set permissions on staging
	chmod -R root:root staging/*
	#  copy from staging into loopback fs
	cp -a staging/* mountpoint/
	#  ??other magics??

busybox : staging
	#copy config file
	cp bbconfig busybox-${BUSYBOXVERSION}/.config
	#build busybox
	cd busybox-${BUSYBOXVERSION}
	make
	#copy to staging area
	make CONFIG_PREFIX=${PWD}/staging install
	#setuid root busybox
	cd ${PWD}

libs : busybox migtorture staging
	#ldd the binaries?
	#copy libraries to staging area

scripts : staging
	#copy scripts from git to staging area

migtorture : staging
	#build migtorture
	cd ${GITROOT}/2.6/tools/migtorture
	make
	#copy to staging area
	cp -a * ${PWD}/staging/migtorture/

staging :
	rm -rf staging/
	mkdir -p staging/bin staging/etc staging/sbin staging/lib staging/proc \
	staging/sys staging/tmp staging/migtorture staging/usr/bin \
	staging/usr/sbin

