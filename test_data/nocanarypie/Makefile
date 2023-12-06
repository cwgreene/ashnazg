all: nocanarypie nocanarypie2

nocanarypie: nocanarypie.c
	gcc -std=c99 -no-pie nocanarypie.c -o nocanarypie -fno-stack-protector -Wno-deprecated-declarations

nocanarypie2: nocanarypie2.c
	gcc -std=c99 -no-pie nocanarypie2.c -o nocanarypie2 -Wno-deprecated-declarations -fno-stack-protector

nocanarypie3: nocanarypie3.c
	gcc -std=c99 -no-pie nocanarypie3.c -o nocanarypie3 -Wno-deprecated-declarations -fno-stack-protector

nocanarypie4: nocanarypie3.c
	gcc -std=c99 -no-pie nocanarypie3.c -o nocanarypie4 -Wno-deprecated-declarations -fno-stack-protector
