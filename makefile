MKD = mkdir
TMPDIR = /tmp
TMPFILE = ${TMPDIR}/no_read_permission

all: /tmp/dno_read_permission /tmp/no_read_permission fend
 
/tmp/dno_read_permission: 
	$(MKD) $@ 
	chmod 000 $@

${TMPFILE}: ${TMPDIR}
	pwd > $@
	chmod 000 $@

fend: fend.c
	gcc -o fend fend.c -I. 

.PHONY: all 
