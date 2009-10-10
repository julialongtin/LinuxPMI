#!/bin/bash

GITDIR=~/asciidoc/LinuxPMI/
TMPAWB=/tmp/awb
AWBPATH=~/asciidoc/awb-0.1/
WEBSITE=/var/www/asciidocs/
asciidocs=`cat ${GITDIR}/asciidocs`


echo "pulling git"
cd ${GITDIR} && git pull

echo "making required awb directories"
rm -rf ${TMPAWB}
mkdir -p ${TMPAWB}/src/
touch ${TMPAWB}/src/.ignore
mkdir -p ${TMPAWB}/html/

echo "copying asciidoc files"
for each in $asciidocs; do {
  mkdir -p ${TMPAWB}/src/`dirname $each`
  cp ${GITDIR}/$each ${TMPAWB}/src/$each.txt
} done;

echo "running awb"
cd ${TMPAWB} && ${AWBPATH}/awb LinuxPMIDocs

rm -rf $WEBSITE
cp -a ${TMPAWB}/html/ $WEBSITE
mv ${WEBSITE}/sitemap.xml /var/www/