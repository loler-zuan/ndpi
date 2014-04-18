INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a  /lib64/libipq.so
FLAGS=-g #-fno-color-diagnostics
server: Server.c Makefile ../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) Server.c -o server $(LIB) -lpthread
client: Client.c 
	gcc $(FLAGS) $(INC) Client.c -o client $(LIB) -lpthread -lcurses
clean:
	\/bin/rm -f client server
