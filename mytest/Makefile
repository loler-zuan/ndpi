INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a  /lib64/libipq.so
FLAGS=-g #-fno-color-diagnostics
pcapReader: testApi.c Makefile ../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) testApi.c -o pcapReader $(LIB) -lpthread -lcurses

clean:
	\/bin/rm -f pcapReader
