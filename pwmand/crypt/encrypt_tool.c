#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(const char *bin) {
  printf("Encrypt a config file for pwand\n");
  printf("Usage: %s input output\n", bin);
  printf("You will be prompted for a password.\n", bin);
}

int main(int argc, char **argv) {
  if(argc != 3) {
    usage(argv[0]);
    exit(0);
  }

  char *pass_1 = (char*)malloc(sizeof(char) * 128);
  char *pass_2 = (char*)malloc(sizeof(char) * 128);

  printf("Enter the password: ");
  gnu_getpass_stdin(pass_1);
  printf("\n");
  printf("Repeat the password: ");
  gnu_getpass_stdin(pass_2);
  printf("\n");

  if(strcmp(pass_1, pass_2) != 0) {
    printf("Passwords are not equal!\n");
  } else {
    char *hash = (char *)malloc(sizeof(char)*64);
    char *pass = (char *)malloc(sizeof(char)*32);
    sha256(pass_1, hash);
    strncpy(pass, hash, 32);

    encrypt(pass, argv[1], argv[2]);
  }
  return 0;
}
