CFLAGS=-Os -lpcap -lnet -Wall -Wextra -pedantic

all: exhaustcp

exhaustcp: exhaustcp.c pcaputil.c
	${CC} ${CFLAGS} -o $@ $^

clean:
	${RM} exhaustcp

.PHONY: clean
