INC=-I../../src/include
FLAGS=-g 
SCLI = Client.c
client: $(SCLI)
	gcc $(FLAGS) $(INC) $(SCLI) -o client $(LIB) -lpthread -lcurses
clean:
	\/bin/rm -f client
