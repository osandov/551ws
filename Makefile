ALL_CFLAGS := -Wall -std=c99 -D_XOPEN_SOURCE=700 -g $(CFLAGS)

551ws: 551ws.o
	$(CC) $(ALL_CFLAGS) -o $@ $^ -l http_parser

%.o: %.c
	$(CC) $(ALL_CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -f 551ws.o 551ws
