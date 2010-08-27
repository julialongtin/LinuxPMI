/*
 *	Copyright (C) 2010 Ashley 'spook' Wiren <ash@spooksoftware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; version 2 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/* location of where proc file inside of /proc/$PID/ */
char *const whereloc = "pms/where";
/* max length of /proc/$PID/whereloc */
#define PATHLENGTH 30
/* max length of text contained in /proc/$PID/whereloc */
#define WHERELENGTH 20
/* global where, FIXME could be done better -spook */
char buffer[WHERELENGTH];

/* tedious number of messages */
void
message (char* binary, char *msg)
{
  printf("%s %d: %s\n", binary, (int) getpid (), msg);
}

/* check if we're running on a pmi enabled kernel */
int
pmikernel (void)
{
  char filename[PATHLENGTH];
  int returnvalue;
  struct stat *discard = malloc(sizeof(stat));
  sprintf(filename,"/proc/%d/%s", (int) getpid(), whereloc);
  returnvalue = stat(filename,discard);
  free(discard);
  return returnvalue;
}

/* read process location */
/* returns the current location */
char *
where (pid_t pid)
{
  FILE *fd;  /* this code block is horrible -spook */
  int length;
  char filename[PATHLENGTH];
  sprintf(filename,"/proc/%d/%s", (int) pid, whereloc);
  fd = fopen(filename,"r");
  length = (int) fread(buffer, sizeof(char), WHERELENGTH, fd);
  fclose(fd);
  return buffer;
}

/* migrates a process */
void
migrate (pid_t pid, char *location)
{
  FILE *fd;  /* this code block is also horrible -spook */
  char filename[PATHLENGTH];
  sprintf(filename,"/proc/%d/%s", (int) pid, whereloc);
  fd = fopen(filename,"w");
  fwrite(location,sizeof(char),WHERELENGTH,fd);
  fclose(fd);
}
