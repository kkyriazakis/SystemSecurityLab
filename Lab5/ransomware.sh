#!/bin/bash

dir=$1
x=$2

if test "$#" -ne 2; then
    echo "Illegal number of parameters. Use tool as shown below:"
	echo "   ./ransomware.sh path X"
	x=0
fi

mkdir -p $dir
# Create X text files
for ((i=0;i<$x;i++))
do
	fname=$dir$i.txt
	LD_PRELOAD=./logger.so ./test_aclog -c ${fname}	
done

# Encrypt X text files and delete originals
for ((i=0;i<$x;i++))
do
	fname=$dir$i.txt
	LD_PRELOAD=./logger.so ./test_aclog -e ${fname}	
	rm $fname
done
