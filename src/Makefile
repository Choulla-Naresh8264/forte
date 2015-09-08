CC=gcc
FLAGS=-Wall -std=c99
LIBRARIES=-L /usr/local/lib/ -lcrypto -lssl -lpbc -lgmp
INCLUDES=-I /usr/local/include/pbc/

all: cbc.o

cbc.o: cbc.c
	$(CC) $(FLAGS) -c cbc.c $(INCLUDES) $(LIBRARIES)

clean:
	rm -rf *.o *.so
