#include <unistd.h>
#include <stdio.h>

int main() {
    char buf[16];
    read(0, buf, 16);
    puts(buf);
}
