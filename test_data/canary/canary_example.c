void func() {
    char buf[8];
    printf("Here's the canary %p\n", *(void **)(buf+8));
    gets(buf);
}

int main() {
    func();
}
