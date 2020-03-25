#  Makefile for infect

CC = gcc
CFLAGS = -Wall -Wextra

infect: infect.c

clean:
	rm -f infect

.PHONY: test
test:
	cp /bin/bash /tmp/bash
	./infect -li /tmp/bash

.PHONY: watch-test
watch-test:
	find infect | entr -c make test

.PHONY: watch
watch:
	find infect.c | entr -c make
