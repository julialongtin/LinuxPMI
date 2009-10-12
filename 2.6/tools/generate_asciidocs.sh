#!/bin/bash

GITDIR=~/asciidoc/LinuxPMI
TMPAWB=/tmp/awb
AWBPATH=~/asciidoc/awb-0.1
WEBSITE=/var/www/asciidocs
asciidocs=`cat ${GITDIR}/asciidocs`
WWWDIR=/var/www

# awb.conf variables
# the name 'LinuxPMIDocs' causes problems, due to uppercasing uppercase. filed with upstream.
CONFFILEDIR=~/.awb
NAME=website
WEBURL="http://linuxpmi.org/asciidocs"
ASCIIDOCOPT=""


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

cat > ${CONFFILEDIR}/awb.conf <<EOF
[${NAME}]
siteroot: ${TMPAWB}
baseurl: ${WEBURL}
asciidoc options: ${ASCIIDOCOPT}
EOF

echo "running awb"
cd ${TMPAWB} && ${AWBPATH}/awb ${NAME} 2> ${TMPAWB}/error.log

#mail linuxpmi-dev@solarnetone.org < ${TMPAWB}/error.log

rm -rf $WEBSITE
cp -a ${TMPAWB}/html/ $WEBSITE
mv ${WEBSITE}/sitemap.xml ${WWWDIR}
