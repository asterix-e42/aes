#!/bin/sh
gcc main.c || exit;
i=0
while true; do 
	head -c 4085 /dev/urandom > test;
	head -c 16 /dev/urandom > key;
	./a.out test 2>/dev/null 3>decipher;
	GG=`diff test decipher`;
	if [[ -n $GG ]]
	then
		break
	fi
	echo $i good;
	i=$(( $i + 1 ));
done
