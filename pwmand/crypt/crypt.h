/*
  crypt header - Defines crypt settings. Requires a recompile

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

#ifndef PWMAND_CRYPT_CRYPT_H
#define PWMAND_CRYPT_CRYPT_H

#include <openssl/evp.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#define BUF_CRYPT_SIZE 256 //ipsize
#define BUF_PLAIN_SIZE 256 + EVP_MAX_BLOCK_LENGTH //opsize

#define IV_SIZE 8
#define KEY_SIZE 32

unsigned char iv[IV_SIZE];
unsigned char key[KEY_SIZE];

#define BASE_IV "TKC4i5EX"

#endif
