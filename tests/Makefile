.PHONY: all test read_test
FLAG = -O2 -g

all: test read_test

test: test.c
	gcc $(FLAG) -o $@ $<

read_test: read_test.c
	gcc $(FLAG) -o $@ $<
