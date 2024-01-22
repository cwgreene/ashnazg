all: unterminated_buffer

# basic 'gets' test
unterminated_buffer: unterminated_buffer.c
	gcc -std=c99 -no-pie -fno-stack-protector -Wno-deprecated-declarations $< -o $@
