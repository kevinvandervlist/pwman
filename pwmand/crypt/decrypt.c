/*
  Decrypt a file. Backend code. 

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

int decrypt(char *passkey, char *file) {
  decrypt_fp(passkey, file, stdout);
}

int decrypt_path(char *passkey, char *file, char *destfile) {
  FILE *fp_dest = fopen(destfile, "wb");
  decrypt_fp(passkey, file, fp_dest);
}

int decrypt_fp(char *passkey, char *file, FILE *dest) {
  // Set the iv
  memset(iv, 0, IV_SIZE);
  strcpy(iv, BASE_IV);

  // Set the key
  memset(key, 0, KEY_SIZE);
  strcpy(key, passkey);

  // Set the rest of the vars
  unsigned char *buf_crypt;
  unsigned char *buf_plain;
  unsigned char *buf_plain_final;
  int buf_plain_len = BUF_PLAIN_SIZE;

  buf_crypt = (unsigned char *) malloc(sizeof(unsigned char) * BUF_CRYPT_SIZE);
  buf_plain = (unsigned char *) malloc(sizeof(unsigned char) * BUF_PLAIN_SIZE);
  buf_plain_final = (unsigned char *) malloc(sizeof(unsigned char) * BUF_PLAIN_SIZE);

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), key, iv);

  // Open the crypted file. 
  FILE *fd_crypt = fopen(file, "r");

  int n = 0;
  while(1) {
    memset(buf_crypt, 0, BUF_CRYPT_SIZE);
    if ((n = fread(buf_crypt, 1, BUF_CRYPT_SIZE, fd_crypt)) == -1) {
      perror("Failed to read file.\n");
      return 1;
      break;
    } else if (n == 0) {
      // No more bytes read
      break;
    }

    memset(buf_plain, 0, BUF_PLAIN_SIZE);
    memset(buf_plain_final, 0, BUF_PLAIN_SIZE);

    if (EVP_DecryptUpdate(&ctx, buf_plain, &buf_plain_len, buf_crypt, n) != 1) {
      fprintf(dest, "Can't decrypt block.\n");
      return 2;
    }

    // We now have a plain text block; copy the decrypted parts
    memcpy(buf_plain_final, buf_plain, buf_plain_len);
    // buff_plain_final contains the decrypted content
    fprintf(dest, "%s", buf_plain_final);
  }
  int final_len = 0;
  memset(buf_plain_final, 0, BUF_PLAIN_SIZE);

  if (EVP_DecryptFinal(&ctx, buf_plain + buf_plain_len, &final_len) != 1) {
    perror("Error in final decrypt.");
    return 4;
  }
  // 
  memcpy(buf_plain_final, buf_plain+buf_plain_len, final_len);
  // buff_plain_final contains the decrypted content
  fprintf(dest, "%s", buf_plain_final);

  EVP_CIPHER_CTX_cleanup(&ctx);
  return 0;
}
