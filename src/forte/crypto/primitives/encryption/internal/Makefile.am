CC=gcc
FLAGS=-Wall -std=c99
EXTERNALLIBRARIES=-L /usr/local/lib/ -lcrypto -lssl -lpbc -lgmp
EXTERNALINCLUDES=-I /usr/local/include/

all:
	$(CC) $(FLAGS) -c cbc_bebgw.c $(EXTERNALINCLUDES) $(EXTERNALLIBRARIES)
	$(CC) $(FLAGS) -c cbc_dummy.c $(EXTERNALINCLUDES) $(EXTERNALLIBRARIES)
	$(CC) $(FLAGS) -c cbc_rsa.c $(EXTERNALINCLUDES) $(EXTERNALLIBRARIES)
