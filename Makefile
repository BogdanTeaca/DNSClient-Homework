all: build

build: dnsclient.c
	gcc dnsclient.c -o dnsclient

run: dnsclient
	./dnsclient yahoo.com NS

clean:
	rm -f *.o dnsclient 


