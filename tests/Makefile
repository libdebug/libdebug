.PHONY: all test read_test write_test
FLAG = -O2 -g

all: test read_test write_test

test: test.c
	gcc $(FLAG) -o $@ $<

read_test: read_test.c
	gcc $(FLAG) -o $@ $<

write_test: write_test.c
	gcc $(FLAG) -o $@ $<
