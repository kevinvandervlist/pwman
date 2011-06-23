/*
  pwman header - Defines the function of pwman that is linked against.
  Use this header as API for software that has to use pwman

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

#ifndef LIBPWMAN_H
#define LIBPWMAN_H

// WARNING!!!
// Changing this requires recompiling pwmand and libpwman

// Base IPC seed - change this to a binary file of 
// this library in production. For now - echo. 
#define IPC_SEED "/bin/echo"
// Max login username length
#define CREDUSERLEN 256
// Max password length
#define CREDPASSLEN 256
// Password file
#define CONFIG "config.crypted"
// Crypted config can be created from a normal one with pwmand_encrypt
// Password of config.crypted = "pwmand"
// #define CONFIG "config.crypted"
// Crypted config? 1 == false; 0 == true
#define CONFIG_CRYPTED 0

// END OF WARNING!!!

// Struct to store user information
// Defines CREDUSERLEN and CREDPASSLEN can be found
// in libpwman_internal.h. Changing this requires recompiling!
// Defaults CREDUSERLEN : 256
// Defaults CREDPASSLEN : 256
typedef struct _credentials {
  char username[CREDUSERLEN];
  char password[CREDPASSLEN];
} credentials;

// Get credentials (if granted) of appname. 
// Returns 
enum pwman_result c_getcred(credentials*);

enum pwman_result {
  // Succesfull means it's zero
  SUCCESS = 0,
  // Can't find program path of binary
  PRGPATH = 1,
  // Can't find username of euid
  USERNOTFOUND = 2,
  // Can't get channel id
  FTOKERR = 4,
  // Can't open channel
  // Probably pwmand is not running
  MSQIDERR = 8,
  // Can't write channel
  CHANWRITEERR = 16,
  // Can't get reply
  CHANREADERR = 32,
  // Access denied
  DENIED = 64
};

#endif
