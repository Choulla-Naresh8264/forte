all: test

test: test.o cbc.o
    gcc -Wall -std=c99 -o test test.o cbc.o

test.o: test.c
    gcc -Wall -std=c99 test.c

cbc.o: cbc.c
    gcc -Wall -std=c99 cbc.c
