#!/bin/sh

echo "Recording..."
env LD_PRELOAD="$PWD/551record.so" 551R2="/tmp/r2.log" ./551ws "$@" &
sleep 1
curl -sv "http://127.0.0.1:8080/index.html"
kill -TERM $!
wait

echo

echo "Replaying..."
env LD_PRELOAD="$PWD/551replay.so" 551R2="/tmp/r2.log" ./551ws "$@"
