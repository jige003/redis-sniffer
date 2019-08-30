CC=gcc 
LDFLAGS= -lpcap  -lhiredis
CFLAGS= -Wall -g
SOURCE= redis-sniffer.c
OBJS=$(SOURCE:.cc=.o)
TARGET= redis-sniffer

.c.o:
	$(CC) $(CFLAGS) $< -o $@

all: release

release: $(OBJS)
	$(CC)  -o $(TARGET) $^ $(LDFLAGS)


clean:
	rm -f  *.o  $(TARGET)

