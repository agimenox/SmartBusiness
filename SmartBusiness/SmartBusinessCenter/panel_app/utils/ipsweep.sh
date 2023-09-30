#!/bin/bash
if [ "$1" == "" ]
then
echo "Need a network address as argument."
echo "Define the three octects of the network: Example: 192.168.0"

else
for ip in $(seq 1 254); do
ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
fi
#How to call it: ./ipsweep.sh + Argument(network) 192.168.0
#If we Save it into a File(iplist.txt) we can run
#for ip in $(cat iplist.txt); do nmap -p 80 -T4 $ip & done

