CFLAGS=-Wall

all: ubidiscover

ubidiscover: ubidiscover.o
	gcc ubidiscover.o -o ubidiscover

clean:
	rm -f ubidiscover.o ubidiscover
