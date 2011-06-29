/*
  pwman daemon - pwman daemon which listenes to incoming password requests.
  Suplies (or denies) the information asked for by the request

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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#include "../libpwman/libpwman.h"
#include "../libpwman/libpwman_internal.h"
#include "passwd_parser.h"

int msqid;
program *list;

// Gracefully shut down. 
void sigint_handler(int sig) {
  printf("Received TERM signal, shutting down...\n");
  if (msgctl(msqid, IPC_RMID, NULL) == -1) {
    // Failed to close queue
    perror("msgctl");
    exit(1);
  }
  // Free passwd list memory
  passwd_cleanup(list);
  exit(0);
}

int main() {
  msgbuf buf;
  key_t key;
  // Parse the passwd file, and fill the needed struct
  list = (program *)malloc(sizeof(program));
  if(parse_passwd_file(list) == 1) {
    printf("Can't parse config.\n");
    exit(1);
  }

  // Catch Ctrl-C / SIGINT to exit the daemon, and close the channel. 
  struct sigaction sa;
  sa.sa_handler = sigint_handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    // Failed
    perror("sigaction - Can't gracefully shutdown");
    exit(1);
  }

  // Get unique key for this channel.
  if ((key = ftok(IPC_SEED, IPC_SEED_KEY)) == -1) {
    // Failed
    perror("ftok");
    exit(1);
  }
  // Open the message channel. 
  if ((msqid = msgget(key, 0666 | IPC_CREAT)) == -1) {
    // Failed
    perror("msgget");
    exit(1);
  }

  while(1) {
    // Retrieve next msg - channel <= abs(2)
    if (msgrcv(msqid, &buf, sizeof(msgbuf) - sizeof(long), -MSGRCVDEFCHAN, 0) == -1) {
      // Failed
      perror("msgrcv");
      exit(1);
    }
    // Parse the msg buffer.
    // Update buf.mtype so it's incremented
    buf.mtype++;
    char *u = buf.req.user;
    char *p = buf.req.path;
    char *auth_u = buf.rpl.username;
    char *auth_p = buf.rpl.password;
    printf("Recv'd: %s:%s\n", buf.req.user, buf.req.path);
    passwd_scan(u, p, list, auth_u, auth_p);
    // Reply data, if found
    if(msgsnd(msqid, &buf, sizeof(msgbuf) - sizeof(long), 0) == -1) {
      // Failed
      perror("msgsnd");
      exit(1);
    }
  }
  // Unreachable
  exit(0);
}
