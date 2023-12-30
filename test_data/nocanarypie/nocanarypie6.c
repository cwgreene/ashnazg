#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char *gets(char *s);

void rop_me() {
    __asm__ ("pop %rdi\n\t"
             "ret\n\t");
}

void deprecated(char *buf) {
    gets(buf);
}

void vulnfunction() {
    char local[8];
    puts("Oh my, this function is not vulnerable");
    read(0, local, 8);
}

int subfunction() {
    char password[32];
    //fread(password, 1, 16, stdin);
    fread(password, 1, 4, stdin);

    if (strcmp(password, "p\n") == 0) {
        vulnfunction();
    } else {
        puts("That was not the password!\n");
    }
    return 0;
}

int distraction(int a, int b) {
    return a + b;
}

int main() {
    int x = distraction(3, 8);
    for(int i = 0; i < 10; i++) {
        printf("%d ", distraction(3, i));
    }
    printf("\n");
    subfunction();
    puts("Well, that was fun!\n");
}
