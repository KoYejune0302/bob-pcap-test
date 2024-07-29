LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.o
	$(CC) -o $@ $^ $(LDLIBS)

pcap-test.o: pcap-test.c pcap-test.h
	$(CC) -c pcap-test.c

clean:
	rm -f pcap-test *.o
