all: test

test: test/test.o cbc.o
    gcc -Wall -std=c99 -o test/cbc_test test/test.o cbc.o

test/test.o: test/test.c
    gcc -Wall -std=c99 test/test.c

cbc.o: cbc.c
    gcc -Wall -std=c99 cbc.c
