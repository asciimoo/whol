#!/usr/bin/env ksh

#.---------------------------------------------
#              (W|H)all Of Lame
#
#,---------------------------------------------

IFACE='wlan0'
DIR='/tmp'
FIFO='whol_pipe'
DSNIFF_FIFO='whol_dsniff_pipe'
QUIET=0
CHANNEL=0
DPREFIX=/tmp/whol_tdump


destruct() {
    if [[ "$STATUS" -gt 0 ]] ; then return; fi
    echo "exitting.."
    R=0
    STATUS=$((STATUS+1))
    if [[ "$1" != "" ]] ; then kill $1; fi
    airmon-ng stop mon0
    rm $DIR/$FIFO
    [[ $DSNIFF ]] && rm $DIR/$DSNIFF_FIFO
    # TODO more sophisticated destruction..
    [[ $DSNIFF ]] && killall dsniff
}

usage() {
    echo -e "(W|H)all of lame - (C) 2010 Adam Tauber

    Usage:

        whol -c [wireless channel] <options>

    Options:

        -c, --channel        <int> : Channel of open wifi networks
        -i, --interface      <str> : Wireless interface name
        -f, --filter         <str> : Pcap filter expression
        -r, --relevance    <float> : Filter output (default is 10)
        -w, --write-file     <str> : Write the original traffic to file (pcap format)
        -h, --help                 : Displays this usage screen
        -d, --dsniff               : Use dsniff
        -q, --quiet                : Quiet mode (no visual output)
"
}

ARGS=`getopt -n whol -u -l channel:,help,quiet,interface:,write-file:,filter:,relevance:,dsniff c:r:f:i:w:hqd $*`
[[ $? != 0 ]] && {
         usage
         exit 1
     }
set -- $ARGS
for i
do
  case "$i" in
        -c|--channel          ) shift; CHANNEL=$1; shift;;
        -q|--quiet            ) shift; QUIET=1;;
        -i|--interface        ) shift; IFACE=$1; shift;;
        -f|--filter           ) shift; FILTER=$1; shift;;
        -w|--write-file       ) shift; W_FILE=$1; shift;;
        -d|--dsniff           ) shift; DSNIFF=1;;
        -r|--relevance        ) shift; RELEVANCE='-r '$1; shift;;
        -h|--help             ) shift; usage; exit 1;;
  esac
done

[[ $CHANNEL == 0 ]] && {
    echo '[!] Wrong wireless channel'
    usage
    exit 1
}

mkfifo $DIR/$FIFO
airmon-ng start $IFACE 0 $( if [ $QUIET -eq 1 ] ; then echo ' >/dev/null'; fi)

airodump-ng_wholmod -o pcap -w $DIR/$FIFO -t OPN -c $CHANNEL mon0 -p -q&
APID=$!

trap "destruct $APID" INT

#ettercap -T -d -m ettertest.log -r $FIFO

[[ $DSNIFF ]] && mkfifo $DIR/$DSNIFF_FIFO && dsniff -m -p $DIR/$DSNIFF_FIFO &

(cat $DIR/$FIFO |\
    tee $([[ $DSNIFF ]] && echo -n $DIR/$DSNIFF_FIFO) $W_FILE | \
        tcpdump -r - -C 1 -w $DPREFIX)&
#       python ./splitpcap.20051126.py | \

TC=1
R=1
rm $DPREFIX*
FILTERPREF=$(./tshark_parser.py -f)
while [ $R == 1 ] ; do 
    [[ ! -f "$DPREFIX$TC" ]] && { sleep 1; continue; }
    if [[ $TC -eq 1 ]]; then
        F=$DPREFIX
    else
        F=$DPREFIX$(( TC-1 ))
    fi
    [[ -f $F ]] && {
    tshark -r $F -R \
        "$FILTERPREF $([[ $FILTER ]] && echo -n ' and ('$FILTER')')" \
            -T pdml 2>/dev/null && rm $F
    }
    TC=$(( $TC+1 ))
done | ./tshark_parser.py $RELEVANCE

R=0
destruct $APID


