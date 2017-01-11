CC		= g++
CFLAGS	= -lpcap -L /usr/local/lib
Target	= traffic_counter
Obj		= main.o

$(Target): $(Obj)
	$(CC) -o $(Target) $(Obj) $(CFLAGS)

%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(Target) *.o
