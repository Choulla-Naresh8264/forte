CC=gcc
FLAGS=-Wall -std=c99
LIBRARIES=-L /usr/local/lib/ -lcrypto -lssl -lpbc -lgmp
INCLUDES=-I /usr/local/include/pbc/

all:
    $(CC) $(FLAGS) -c cbc_bebgw.c $(INCLUDES) $(LIBRARIES)
    $(CC) $(FLAGS) -c cbc_dummy.c $(INCLUDES) $(LIBRARIES)
    $(CC) $(FLAGS) -c cbc_rsa.c $(INCLUDES) $(LIBRARIES)

clean:
	rm -rf *.o *.so
