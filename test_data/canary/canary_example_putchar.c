#include <stdio.h>
void func() {
    char buf[8];
    printf("Here's the canary :");
    for(int i = 0; i < 8;i++) {
        putchar((buf[8+i]));
    }
    puts(""); // run into buffering issues if this isn't used. Investigate.
    gets(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    func();
}
