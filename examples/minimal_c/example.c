/*
  pwman example - Example to show the useage of pwman 

  Copyright (C) 2010 Kevin van der Vlist <kevin@kevinvandervlist.nl>

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
#include <libpwman.h>

int main() {
  credentials cred;
  enum pwman_result res = pwman_getcred(&cred);
  if(res == SUCCESS) {
    printf("Authenticated:\n");
    printf("Username: %s\n", cred.username);
    printf("Password: %s\n", cred.password);
  } else if (res == MSQIDERR) {
    printf("Can't open message channel.\n");
    printf("Daemon pwmand probably isn't running.\n");
  } else {
    printf("Authentication failed:\n");
    printf("Return code: %d\n", res);
  }
  exit(0);
}
