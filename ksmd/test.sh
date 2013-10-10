#!/bin/sh

set -e
set -x

rm -f keys.db
cat sql/schema.sql sql/test-data.sql | sqlite3 keys.db
go build -o ksm && ./ksm -db=keys.db & gopid=$!
sleep 2

http -vv http://localhost:8080/wsapi/decrypt?otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh

kill $gopid

rm -f ksm keys.db
