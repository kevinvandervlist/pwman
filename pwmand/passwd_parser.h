/*
  pwman parser header - Header containing definitions of the parser

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


#ifndef PASSWD_PARSER_H
#define PASSWD_PARSER_H

// Define
#define BUFSIZE 1024

// user struct info
struct _user {
  char *name;
  struct _user *next;
};

typedef struct _user user;

// Group struct info
struct _group {
  char *name;
  struct _group *next;
};

typedef struct _group group;

// Program struct info - contains data from the file. 
struct _program {
  char *path;
  struct _user *user;
  struct _group *group;
  char *username;
  char *password;
  struct _program *next;
};

typedef struct _program program;

// Free malloc()'d memory
void passwd_cleanup(program *);
// Print whole config
void passwd_print(program *);
// Scan passwd file. 
int parse_passwd_file(program *);
// Scan for a valid entry
void passwd_scan(char *, char *, program *p, char *, char *);

#endif
