#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(const char *bin) {
  printf("Decrypt a config file for pwand\n");
  printf("Usage: %s output\n", bin);
  printf("You will be prompted for a password.\n", bin);
}

int main(int argc, char **argv) {
  if(argc != 2) {
    usage(argv[0]);
    exit(0);
  }

  char *pass_1 = (char*)malloc(sizeof(char) * 128);

  printf("Enter the password: ");
  gnu_getpass_stdin(pass_1);
  printf("\n");

  char *hash = (char *)malloc(sizeof(char)*64);
  char *pass = (char *)malloc(sizeof(char)*32);
  sha256(pass_1, hash);
  strncpy(pass, hash, 32);

  decrypt(pass, argv[1]);
  return 0;
}
