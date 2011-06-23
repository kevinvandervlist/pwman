/*
  getpass - Read a password from the terminal; which is secured. 

  from: http://www.gnu.org/s/hello/manual/libc/getpass.html

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

#include <termios.h>
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>
     
size_t gnu_getpass_stdin(char **lineptr) {
  struct termios old, new;
  int nread;
     
  /* Turn echoing off and fail if we can't. */
  if (tcgetattr (fileno (stdin), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
    return -1;
     
  /* Read the password. */
  //nread = getline (lineptr, n, stdin);
  fscanf(stdin, "%128s", lineptr);
     
  /* Restore terminal. */
  (void) tcsetattr (fileno (stdin), TCSAFLUSH, &old);
     
  return nread;
}

void sha256(char *string, char *res) {

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha;
  SHA256_Init(&sha);
  SHA256_Update(&sha, string, strlen(string));
  SHA256_Final(hash, &sha);

  int i = 0;

  for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(res + (i * 2), "%02x", hash[i]);
  }
  res[64] = 0;
  return;
}
