LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o ethhdr.o mac.o ip.o    
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f tcp-block *.o
