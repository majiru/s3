</$objtype/mkfile

path=/bin
BIN=$home/bin/$objtype/s3

TARG=\
	factotum\
	rm\
	cat\
	ls\
	cp\
	write\

HFILES=\
	xml.h\

</sys/src/cmd/mkmany

$O.factotum: factotum.$O

$O.rm: rm.$O s3.$O cmd.$O

$O.cat: cat.$O s3.$O cmd.$O

$O.ls: ls.$O s3.$O cmd.$O xml.$O

$O.write: write.$O s3.$O cmd.$O xml.$O

$O.cp: cp.$O s3.$O cmd.$O
