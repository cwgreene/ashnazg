#include <stdio.h>
int main() {
    char buffer[10];
    getc(stdin); // stall here.
    puts("Hello world!");
}
