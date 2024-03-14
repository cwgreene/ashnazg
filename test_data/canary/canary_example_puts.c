void func() {
    char buf[8];
    printf("Here's the canary :");
    puts((buf+8+1));
    gets(buf);
}

int main() {
    func();
}
