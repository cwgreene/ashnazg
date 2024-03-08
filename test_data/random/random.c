#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    srand(argc);
    // Angr treats rand as an opaque value.
    long r = rand();
    if (r % 2 == 0) {
        printf("Secret A\n");
    } else {
        printf("Secret B\n");
    }
}
