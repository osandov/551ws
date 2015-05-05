ALL_CFLAGS := -Wall -std=c99 -D_GNU_SOURCE -g $(CFLAGS)

551ws: 551ws.o
	$(CC) $(ALL_CFLAGS) -o $@ $^ -lhttp_parser -lseccomp

%.o: %.c
	$(CC) $(ALL_CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -f 551ws.o 551ws
