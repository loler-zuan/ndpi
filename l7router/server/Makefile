INC=-I../../src/include/
LIB=../../src/lib/.libs/libndpi.a  /lib/libipq.so
FLAGS=-g 
SSRC = Server.c communicate.c detection.c iptables_patch.c worker.c parameters.c rules.c
server: $(SSRC) ../../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) $(SSRC) -o server $(LIB) -lpthread
clean:
	\/bin/rm -f server
