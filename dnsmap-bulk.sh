#!/bin/bash
if [[ $# -ne 1 && $# -ne 2 && $# -ne 3 ]]
then
	echo "usage: `basename $0` <domains-file> [results-path] [wordlist-path]";
	echo "e.g.:";
	echo "`basename $0` domains.txt";
	echo "`basename $0` domains.txt /tmp/";
	echo "`basename $0` domains.txt /tmp/ /usr/share/dirbuster/wordlists/directories.jbrofuzz"; 
	exit
fi
for i in `cat $1`
do
	if [[ $# -eq 1 ]] 
	then	
		dnsmap $i &
	elif [[ $# -eq 2 ]] 
	then	
		dnsmap $i -r $2 &
	elif [[ $# -eq 3 ]] 
	then	
		dnsmap $i -r $2 -w $3 &
	fi
done
wait

