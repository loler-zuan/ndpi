INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a  /lib64/libipq.so
FLAGS=-g #-fno-color-diagnostics
pcapReader: pcapReader.c Makefile ../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) pcapReader.c -o pcapReader $(LIB) -lpthread -lcurses  -lpcap

clean:
	\/bin/rm -f pcapReader
