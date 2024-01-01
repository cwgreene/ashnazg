all: nocanarypie nocanarypie2

# basic 'gets' test
nocanarypie: nocanarypie.c
	gcc -std=c99 -no-pie nocanarypie.c -o nocanarypie -fno-stack-protector -Wno-deprecated-declarations

# can navigate to vulnerable function
nocanarypie2: nocanarypie2.c
	gcc -std=c99 -no-pie nocanarypie2.c -o nocanarypie2 -Wno-deprecated-declarations -fno-stack-protector

# can navigate out of vulnerable function after input
nocanarypie3: nocanarypie3.c
	gcc -std=c99 -no-pie nocanarypie3.c -o nocanarypie3 -Wno-deprecated-declarations -fno-stack-protector

# read unsafe
nocanarypie4: nocanarypie4.c
	gcc -std=c99 -no-pie nocanarypie4.c -o nocanarypie4 -Wno-deprecated-declarations -fno-stack-protector

# Input payload must match constraints.
nocanarypie5: nocanarypie5.c
	gcc -std=c99 -no-pie nocanarypie5.c -o nocanarypie5 -Wno-deprecated-declarations -fno-stack-protector

# read safe
nocanarypie6: nocanarypie6.c
	gcc -std=c99 -no-pie nocanarypie6.c -o nocanarypie6 -Wno-deprecated-declarations -fno-stack-protector

# fgets
nocanarypie7: nocanarypie7.c
	gcc -std=c99 -no-pie nocanarypie7.c -o nocanarypie7 -Wno-deprecated-declarations -fno-stack-protector

# fread
nocanarypie8: nocanarypie8.c
	gcc -std=c99 -no-pie nocanarypie8.c -o nocanarypie8 -Wno-deprecated-declarations -fno-stack-protector
