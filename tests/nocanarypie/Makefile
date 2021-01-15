all: nocanarypie nocanarypie2

nocanarypie: nocanarypie.c
	gcc -std=c99 -no-pie nocanarypie.c -o nocanarypie -fno-stack-protector -Wno-deprecated-declarations

nocanarypie2: nocanarypie2.c
	gcc -std=c99 -no-pie nocanarypie2.c -o nocanarypie2 -Wno-deprecated-declarations -fno-stack-protector
