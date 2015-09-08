CC=gcc
FLAGS=-Wall -std=c99
LIBRARIES=-L /usr/local/lib/ -lcrypto -lssl -lpbc
INCLUDES=-I /usr/local/include/pbc/

all:
	$(CC) $(FLAGS) -o cbc_test test.o ../cbc.o $(INCLUDES) $(LIBRARIES)

clean:
	rm -r *.so *.o
