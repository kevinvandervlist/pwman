/*
  Decrypt a file. Frontend tool. 

  Copyright (C) 2011 Kevin van der Vlist <kevin@kevinvandervlist.nl>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.
    
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
    
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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
