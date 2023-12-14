#!/bin/sh
if [ $# -ne 2 ]; then
    echo "Usage: $0 mininet_machine_ip vhost_num"
    exit
fi

#TODO: change the hostname into the ip/hostname of the machine runs mininet/pox
./sr -t 300 -v $2 -r rtable.$2 -s $1 -p 8888 -l $2.pcap
