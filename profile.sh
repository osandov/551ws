#!/bin/sh

benchmark () {
	ab -q -n 100000 -c 50 http://127.0.0.1:8080/index.html
}

make clean
CFLAGS="-DNDEBUG -O2" make

echo "No seccomp"
./551ws ws_noseccomp.conf &
sleep 1
benchmark | tee /tmp/no_seccomp.txt
kill -TERM $!
wait $!

echo "Seccomp"
./551ws ws.conf &
sleep 1
benchmark | tee /tmp/seccomp.txt
kill -TERM $!
wait $!

make clean
CFLAGS="-DNDEBUG -O2 -fstack-protector -D_FORTIFY_SOURCE=2" make

echo "Seccomp+fortify source"
./551ws ws.conf &
sleep 1
benchmark | tee /tmp/seccomp_fortify.txt
kill -TERM $!
wait $!
