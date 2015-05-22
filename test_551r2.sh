#!/bin/sh

ADDR="127.0.0.1:8080"
ROOT="www"

echo "Recording..."
env LD_PRELOAD="$PWD/551record.so" 551R2="/tmp/r2.log" ./551ws -l "$ADDR" -r "$ROOT" -d &
sleep 1
curl -v http://"$ADDR"/index.html
curl -v http://"$ADDR"/index.html -H "If-None-Match: \"$(sha1sum www/index.html | awk '{print $1 }')\""
kill -TERM $!
wait

echo
echo
echo

echo "Replaying..."
env LD_PRELOAD="$PWD/551replay.so" 551R2="/tmp/r2.log" ./551ws -l "$ADDR" -r "$ROOT" -d
