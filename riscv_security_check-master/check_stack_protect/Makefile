#CC=riscv64-unknown-linux-gnu-gcc
#CC=riscv64-unknown-elf-gcc
CC=gcc
#CFLAGS=-Wall -march=rv64imafd -mabi=lp64d -Irocket-rocc-examples/rocc-software/src -Isrc/main/c -Isrc/test/c -static -L/home/yang/MyProject/hardware_supported_taint_project/code/varanus/usr/lib-rv/ -lvaranus

check_stack_protect.rv : main.o
	$(CC) $(CFLAGS) -static -o check_stack_protect.rv main.o


main.o : main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm *.rv *.o