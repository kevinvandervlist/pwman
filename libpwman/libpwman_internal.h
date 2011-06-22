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

#ifndef LIBPWMAN_INTERNAL_H
#define LIBPWMAN_INTERNAL_H

#include "libpwman.h"

// Seed key - any value is ok. 
#define IPC_SEED_KEY 'x'
// Max binary path lenght
#define BINPATHLEN 256
// Max system username length - probably is enough. 
// If not, increase it sufficiently
#define SYSUSERLEN 64
// Default mtype of channel. 
#define MSGRCVDEFCHAN 2

// Struct to store request data
typedef struct _cred_request {
  char user[SYSUSERLEN];
  char path[BINPATHLEN];
} cred_request;

// Struct to communicate over the message queues
typedef struct _msgbuf {
  long mtype;
  cred_request req;
  credentials rpl;
} msgbuf;

#endif
