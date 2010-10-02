opt = -O2 -DEXTENDED_INFOS


all: 
	echo "write a target.. example: make sxd"

testlistener: test/testlistener.c listener.h listener.c list-queue.h list-queue.c listeners/*.c
	gcc -lpthread -lpcap -I. test/testlistener.c listener.c list-queue.c listeners/*.c -o test/testlistener $(opt) 

testlistener-clean:
	rm -f test/testlistener

testtcp: filters/smbstructs.h filters/smbxfers.c filters/smbxfers.h streamassembler.c streamassembler.h streamstructs.h list-queue.c list-queue.h test/testtcp.c byteorder.h
	gcc -lpthread -lpcap -I. filters/smbxfers.c streamassembler.c list-queue.c test/testtcp.c -o test/testtcp $(opt)

testtcp-clean:
	rm -f test/testtcp

sxd: listener.h listener.c list-queue.h list-queue.c listeners/sniff.c filters/smbstructs.h filters/smbxfers.c filters/smbxfers.h streamassembler.c streamassembler.h streamstructs.h list-queue.c list-queue.h sxd.c 
	gcc -I. -lpthread -lpcap  listener.c listeners/sniff.c filters/smbxfers.c streamassembler.c list-queue.c sxd.c  -o sxd $(opt)

sxd-clean:
	rm -f sxd
