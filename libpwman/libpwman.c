/*
  pwman library - Library providing the linking target of the authentication function

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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pwd.h>

#include "libpwman.h"
#include "libpwman_internal.h"

// Private
int getProgramPath(char *name);

enum pwman_result pwman_getcred(credentials *cred) {
  enum pwman_result retval = SUCCESS;
  msgbuf msg;
  int msqid;
  key_t key;

  strcpy(cred->username, "NULL");
  strcpy(cred->password, "NULL");

  // Get the current program name
  if(!getProgramPath(msg.req.path)) {
    retval = PRGPATH;
    return retval;
  }

  // Get username
  uid_t uid = geteuid();
  struct passwd *pw = getpwuid(uid);
  if(pw) {
    strcpy(msg.req.user, pw->pw_name);
  } else {
    // Can't find username of active uid - usrnotfound
    retval = USERNOTFOUND;
    return retval;
  }

  // Get unique key for this channel.
  if ((key = ftok(IPC_SEED, IPC_SEED_KEY)) == -1) {
    // Failed - can't get channel id - ftokerr
    retval = FTOKERR;
    return retval;
  }
  // Open the message channel. 
  if ((msqid = msgget(key, 0666)) == -1) {
    // Failed - Can't open channel - msqiderr
    retval = MSQIDERR;
    return retval;
  }

  // Send the request
  // Daemon listens to <=abs(MSGRCVDEFCHAN)
  msg.mtype = MSGRCVDEFCHAN;
  if(msgsnd(msqid, &msg, sizeof(msgbuf) - sizeof(long), 0) == -1) {
    // Failed - Can't send message over channel - chanwriteerr
    retval = CHANWRITEERR;
    return retval;
  }

  // Now wait for a reply
  if (msgrcv(msqid, &msg, sizeof(msgbuf) - sizeof(long), -(msg.mtype+1), 0) == -1) {
    // Failed - Can't get reply - chanreaderr
    retval = CHANREADERR;
    return retval;
  } else {
    strcpy(cred->username, msg.rpl.username);
    strcpy(cred->password, msg.rpl.password);
  }
  if((strcmp(cred->username, "NULL") == 0) && (strcmp(cred->password, "NULL") == 0) ) {
    // Succesfull communication, but no access granted - denied
    retval = DENIED;
    return retval;
  }
  // Successfull - success
  return retval;
}

int getProgramPath(char *name) {
  // This ought to be enough
  size_t len = readlink("/proc/self/exe", name, (sizeof(char)*BINPATHLEN)-1);
  if(len != -1) {
    name[len] = '\0';
  } else {
    return 0;
  }
  return 1;
}

char *pwman_getUser() {
  credentials cred;
  enum pwman_result res = pwman_getcred(&cred);
  char *ret = (char*)malloc(sizeof(char)*strlen(cred.username));
  strcpy(ret, cred.username);
  return ret;
}

char *pwman_getPass() {
  credentials cred;
  enum pwman_result res = pwman_getcred(&cred);
  char *ret = (char*)malloc(sizeof(char)*strlen(cred.password));
  strcpy(ret, cred.password);
  return ret;
}
