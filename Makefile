ALL_CFLAGS := -Wall -Werror -std=c99 -D_GNU_SOURCE -g $(CFLAGS)

all: 551ws 551record.so 551replay.so

551ws: 551ws.c
	$(CC) $(ALL_CFLAGS) -o $@ $^ -lhttp_parser -lseccomp

551record.so: 551record.c 551r2.h
	$(CC) $(ALL_CFLAGS) -shared -fpic -I. -o $@ $< -ldl

551replay.so: 551replay.c 551r2.h
	$(CC) $(ALL_CFLAGS) -shared -fpic -I. -o $@ $< -ldl

.PHONY: clean
clean:
	rm -f 551ws 551record.so 551replay.so
