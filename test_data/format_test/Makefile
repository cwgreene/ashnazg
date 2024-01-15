all: format_test

format_test: format_test.c
	gcc -std=c99 -no-pie $< -o $@ -Wno-deprecated-declarations
