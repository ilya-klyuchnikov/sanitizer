#include <stdio.h>

char * getName(int i) {
    return "me";
}

int main() {
    printf("hello %s", getName(123));
    return 0;
}