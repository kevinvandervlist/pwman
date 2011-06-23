/*
  Encrypt a file. Backend code. 

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

#include "crypt.h"

int encrypt(char *passkey, char *file, char *dest) {

  // Set the iv
  memset(iv, 0, IV_SIZE);
  strcpy(iv, BASE_IV);

  // Set the key
  memset(key, 0, KEY_SIZE);
  strcpy(key, passkey);

  // Set the rest of the vars
  unsigned char *buf_plain;
  unsigned char *buf_crypt;
  unsigned char *buf_crypt_final;
  int buf_crypt_len = BUF_PLAIN_SIZE;

  buf_plain = (unsigned char *) malloc(sizeof(unsigned char) * BUF_CRYPT_SIZE);
  buf_crypt = (unsigned char *) malloc(sizeof(unsigned char) * BUF_PLAIN_SIZE);
  buf_crypt_final = (unsigned char *) malloc(sizeof(unsigned char) * BUF_PLAIN_SIZE);

  EVP_CIPHER_CTX  ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv);

  // Open the plain file.
  FILE *fd_plain = fopen(file, "r");
  FILE *fd_crypt = fopen(dest, "wb");

  int n = 0;
  while(1) {
    memset(buf_plain, 0, BUF_CRYPT_SIZE);
    if ((n = fread(buf_plain, 1, BUF_CRYPT_SIZE, fd_plain)) == -1) {
      perror("Failed to read file.\n");
      return 1;
      break;
    } else if (n == 0) {
      // No more bytes read
      break;
    }

    memset(buf_crypt, 0, BUF_PLAIN_SIZE);
    memset(buf_crypt_final, 0, BUF_PLAIN_SIZE);

    if (EVP_EncryptUpdate(&ctx, buf_crypt, &buf_crypt_len, buf_plain, n) != 1) {
      printf("Can't encrypt block.\n");
      return 2;
    }

    fwrite(buf_crypt, 1, buf_crypt_len, fd_crypt);
  }

  int final_len = 0;
  memset(buf_crypt_final, 0, BUF_PLAIN_SIZE);

  if (EVP_EncryptFinal(&ctx, buf_crypt + buf_crypt_len, &final_len) != 1) {
    perror("Error in final encrypt.");
    return 4;
  }

  fwrite(buf_crypt+buf_crypt_len, 1, final_len, fd_crypt);
  fclose(fd_crypt);

  EVP_CIPHER_CTX_cleanup(&ctx);
  return 0;
}
