CC=gcc
FLAGS=-Wall -std=c99
LIBRARIES=-L /usr/local/lib/ -lcrypto -lssl -lpbc -lgmp
INCLUDES=-I /usr/local/include/pbc/

all: test

test: test/test.o cbc.o
	$(CC) $(FLAGS) -o test/cbc_test test/test.o cbc.o $(INCLUDES) $(LIBRARIES)

test/test.o: test/test.c
	$(CC) $(FLAGS) -c test/test.c $(INCLUDES) $(LIBRARIES)

cbc.o: cbc.c
	$(CC) $(FLAGS) -c cbc.c $(INCLUDES) $(LIBRARIES)

clean:
	rm -rf *.o *.so
