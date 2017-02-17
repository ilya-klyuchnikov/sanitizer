#include <stdio.h>

char* getName() {
  return "me";
}

int main(int argc, char const *argv[]) {
  printf("%s\n", getName());
  return 0;
}
