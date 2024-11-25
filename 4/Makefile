CC=gcc
OUTPUT_DID=vul_x64
SOURCR_DIR=src
CFLAGS=-fno-stack-protector 
LD= -z execstack -O0 
LD_D= -z execstack 
OBJ=main.o unit.o base64.o
VPATH = ${SOURCR_DIR}:${OUTPUT_DID}

.PHONY: clean

all: dir vul_x64

debug: dir vul_x64-dbg

dyn: dir vul_x64-dyn

vul_x64: ${OBJ}
	${CC}  ${OBJ:%.o=${OUTPUT_DID}/%.o} -o ${OUTPUT_DID}/$@ ${LD}
	#strip -s ${OUTPUT_DID}/$@

vul_x64-dbg: ${OBJ}
	${CC}  ${OBJ:%.o=${OUTPUT_DID}/%.o} -o ${OUTPUT_DID}/$@ ${LD}

vul_x64-dyn: ${OBJ}
	${CC}  ${OBJ:%.o=${OUTPUT_DID}/%.o} -o ${OUTPUT_DID}/$@ ${LD_D}
	#strip -s ${OUTPUT_DID}/$@

dir:
	-mkdir vul_x64

${OBJ}: %.o: %.c
	${CC} -c $< -o ${OUTPUT_DID}/$@ ${CFLAGS}


clean:
	-rm ${OUTPUT_DID}/*.o
	-rm ${OUTPUT_DID}/.gdb_history
	-rm ${OUTPUT_DID}/*.idb
	-rm */peda-session-vul_x64.txt
	-rm peda-session-vul_x64.txt
	-rm */*~
	-rm *~
	-rm ./vul_x64 -rf
