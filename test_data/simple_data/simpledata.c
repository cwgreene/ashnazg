#include <stdio.h>
// This function is completely self contained
// and the vulnerability can be determined
// simply by comparing the target buffer
// and the size parameter.
void vuln_direct() {
	char buf[0x50];
	fgets(buf, 0x100, stdin);
}

// Can we trace local parameters?
void vuln_indirect() {
	char buf[0x50];
	int size = 0x100;
	fgets(buf, size, stdin);
}

// This vulnerability needs to 
// be able to determine if the size
// is larger than the target buffer.
void vuln_param(int size) {
	char buf[0x50];
	fgets(buf, size, stdin);
}

// This vulnerability requires us
// to determine if their are any
// paths that yield the problem.
void vuln_conditional(int size) {
	char buf[0x50];
	if (size == 0) {
		size = 0x50;
	} else if (size == 1) {
		size = 0x100;
	} else {
		size = 0x50;
	}
	fgets(buf, size, stdin);
}

int main() {
	vuln_direct();
	vuln_param(0x100);
	vuln_conditional(1);
}
