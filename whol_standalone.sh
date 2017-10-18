#!/bin/bash

IFACE="$1"
FIFO="/tmp/whol_fifo"
DPREFIX="/tmp/whol_output"
RELEVANCE=10

rm "$DPREFIX"* > /dev/null 2>&1

mkfifo "$FIFO" 2>/dev/null

tcpdump -w "$FIFO" -i "$IFACE" 2>/dev/null &
APID=$!

trap "kill -9 $APID" INT


(cat "$FIFO" | tcpdump -r - -C 1 -w $DPREFIX 2>/dev/null || exit 3)&
BPID=$!

trap "kill -9 $BPID" INT

TC=1
R=1
FILTERPREF=$(./tshark_parser.py -f)
while [ $R == 1 ] ; do
    [[ ! -f "$DPREFIX$TC" ]] && { sleep 1; continue; }
    if [[ $TC -eq 1 ]]; then
        F=$DPREFIX
    else
        F=$DPREFIX$(( TC-1 ))
    fi
    [[ -f $F ]] && tshark -r "$F" -2 -R "$FILTERPREF" -T pdml 2>/dev/null && rm "$F"
    echo "$F parsed" >&2
    TC=$(( $TC+1 ))
done | ./tshark_parser.py $RELEVANCE

R=0
kill -9 $APID 2>/dev/null
kill -9 $BPID 2>/dev/nulD
