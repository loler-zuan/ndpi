INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a  /lib/libipq.so
FLAGS=-g 
SSRC = Server.c communicate.c detection.c iptables_patch.c worker.c
SCLI = Client.c
server: $(SSRC) ../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) $(SSRC) -o server $(LIB) -lpthread
client: $(SCLI)
	gcc $(FLAGS) $(INC) $(SCLI) -o client $(LIB) -lpthread -lcurses
clean:
	\/bin/rm -f client server
