/*
  pwman parser - Parse pwman config

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


#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "passwd_parser.h"
#include "../libpwman/libpwman.h"

// private
int isComment(char *);
void init_group(group *);
void init_program(program *);
void init_user(user *);
void parseLine(program *, char *);

int parse_passwd_file(program *list) {
  FILE *conf_fd = fopen(CONFIG, "r");
  char buf[BUFSIZE];
  init_program(list);

  if(conf_fd != NULL) {
    program *iter = list;
    program *prev;
    while(fgets(buf, sizeof(buf), conf_fd) != NULL) {
      // Ok, line fetched. 
      if(!isComment(buf)) {
	if(iter == NULL) {
	  iter = (program *)malloc(sizeof(program));
	  init_program(iter);
	  prev->next = iter;
	}
	parseLine(iter, buf);
	prev = iter;
	iter = prev->next;
      }
    }
    fclose(conf_fd);
  }
  //passwd_print(list);
  return 0;
}

void passwd_cleanup(program *p) {
  // Cleanup whole struct. Awfull lot of free()'ing
  program *prog = p;
  user *u;
  group *g;
  while(prog != NULL) {
    free(prog->path);
    u = prog->user;
    while(u != NULL) {
      free(u->name);
      user *user_t = u->next;
      free(u);
      u = user_t;
    }
    g = prog->group;
    while(g != NULL) {
      free(g->name);
      group *group_t = g->next;
      free(g);
      g = group_t;
    }
    free(prog->username);
    free(prog->password);
    program *next = prog->next;
    free(prog);
    prog = next;
  }
}

void passwd_print(program *p) {
  program *prog = p;
  user *u;
  group *g;
  while(prog != NULL) {
    printf("Prog:\n");
    printf("Path - %s\n", prog->path);
    u = prog->user;
    while(u != NULL) {
      printf("\tuser - %s\n", u->name);
      user *user_t = u->next;
      u = user_t;
    }
    g = prog->group;
    while(g != NULL) {
      printf("\tgroup - %s\n", g->name);
      group *group_t = g->next;
      g = group_t;
    }
    printf("username - %s\n", prog->username);
    printf("password - %s\n", prog->password);
    program *next = prog->next;
    prog = next;
  }
}

int isComment(char *line) {
  if(line[0] == '#') {
    return 1;
  }
  if(line[0] == ' ') {
    return 1;
  }
  if(line[0] == '\n') {
    return 1;
  }
  return 0;
}

void parseLine(program *list, char *line) {
  char buf[BUFSIZE];
  memset(buf, '\0', BUFSIZE);
  int c = 0;
  int b = 0; //buf counter
  int s = 0; //status bool
  // Path:
  for(c = 0; c < strlen(line); c++) {
    if(line[c] == ':') {
      // End
      c++;
      break;
    } else {
      // Path character
      buf[b++] = line[c];
    }
  }
  list->path = (char *)malloc(sizeof(char) * (b+1));
  strcpy(list->path, buf);
  // User+group
  memset(buf, '\0', b);
  b = 0;
  user *usr = list->user;
  user *usr_t;

  group *grp = list->group;
  group *grp_t;
  for(; c < strlen(line); c++) {
    if(line[c] == ':') {
      // End
      c++;
      break;
    } else if(line[c] == ',') {
      // Splitter - add entry
      if(s == 0) {
	// User
	usr = (user *)malloc(sizeof(user));
	init_user(usr);
	usr->name = (char *)malloc(sizeof(char) * (b+1));
	strcpy(usr->name, buf);
	usr_t = list->user;
	list->user = usr;
	list->user->next = usr = usr_t;
      } else if (s == 1) {
	// Group
	grp = (group *)malloc(sizeof(group));
	init_group(grp);
	grp->name = (char *)malloc(sizeof(char) * (b+1));
	strcpy(grp->name, buf);
	grp_t = list->group;
	list->group = grp;
	list->group->next = grp = grp_t;
      }
      s = 0;
      memset(buf, '\0', b);
      b = 0;
    } else if(line[c] == '%') {
      // Group identifier
      s = 1;
    } else {
      buf[b++] = line[c];
    }
  }
  /* Dirty hack to add last user or group */
  if(s == 0) {
    // User
    usr = (user *)malloc(sizeof(user));
    init_user(usr);
    usr->name = (char *)malloc(sizeof(char) * (b+1));
    strcpy(usr->name, buf);
    usr_t = list->user;
    list->user = usr;
    list->user->next = usr = usr_t;
  } else if (s == 1) {
    // Group
    grp = (group *)malloc(sizeof(group));
    init_group(grp);
    grp->name = (char *)malloc(sizeof(char) * (b+1));
    strcpy(grp->name, buf);
    grp_t = list->group;
    list->group = grp;
    list->group->next = grp = grp_t;
  }
  s = 0;
  memset(buf, '\0', b);
  b = 0;
  /* End dirty hack */
  // Username
  memset(buf, '\0', b);
  b = 0;
  for(c; c < strlen(line); c++) {
    if(line[c] == ':') {
      // End
      c++;
      break;
    } else {
      // Path character
      buf[b++] = line[c];
    }
  }
  list->username = (char *)malloc(sizeof(char) * (b+1));
  strcpy(list->username, buf);

  // Password
  memset(buf, '\0', b);
  b = 0;
  for(c; c < strlen(line); c++) {
    if(line[c] == ':') {
      // End
      c++;
      break;
    } else if(line[c] == '\n') {
      // End
      c++;
      break;
    } else {
      // Path character
      buf[b++] = line[c];
    }
  }
  list->password = (char *)malloc(sizeof(char) * (b+1));
  strcpy(list->password, buf);
  return;
}

void init_program(program *list) {
  list->path = NULL;
  list->user = NULL;
  list->group = NULL;
  list->username = NULL;
  list->password = NULL;
  list->next = NULL;
}

void init_user(user *user) {
  user->name = NULL;
  user->next = NULL;
}

void init_group(group *group) {
  group->name = NULL;
  group->next = NULL;
}

void passwd_scan(char *usr, char *path, program *p, char *rpl_u, char *rpl_p) {
  // Init @ none
  strcpy(rpl_u, "NULL");
  strcpy(rpl_p, "NULL");
  // First: Dow we have a binary with the same name?
  program *prog = p;
  user *u;
  group *g;
  while(prog != NULL) {
    if(strcmp(prog->path, path) == 0) {
      // Same program name - check user stuff
      u = prog->user;
      while(u != NULL) {
	if(strcmp(u->name, usr) == 0) {
	  // Same user - print user+pass
	  strcpy(rpl_u, prog->username);
	  strcpy(rpl_p, prog->password);
	  return;
	} else {
	  // Next user
	  user *user_t = u->next;
	  u = user_t;
	}
      }
      g = prog->group;
      while(g != NULL) {
	if(groupHasMember(g->name, usr)) {
	  // Same group - print user+pass
	  strcpy(rpl_u, prog->username);
	  strcpy(rpl_p, prog->password);
	  return;
	} else {
	  // Next group
	  group *group_t = g->next;
	  g = group_t;
	}
      }
      // binary hit, but no valid creds
      return;
    } else {
      // Not the same name - next
      program *next = prog->next;
      prog = next;
    }
  }
  return;
}

int groupHasMember(char *group_name, char *user_name) {
  struct group *g;
  char **mem;
  // Init
  setgrent();
  while((g = getgrent()) != NULL) {
    if(strcmp(g->gr_name, group_name) == 0) {
      // Same group name; member?
      mem = g->gr_mem;
      while(*mem != NULL) {
	if(strcmp(*mem, user_name) == 0) {
	  // User i in group - true
	  return 1;
	}
	// Go to next member
	*mem++;
      }
    }
  }
  endgrent();
  // Not in group
  return 0;
}
