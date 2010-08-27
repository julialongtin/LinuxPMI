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

#include <signal.h>    /* signal kill */
#include <stdio.h>     /* fopen fclose fread fwrite printf sprintf */
#include <stdlib.h>    /* malloc free */
#include <sys/types.h> /* kill stat getpid */
#include <sys/stat.h>  /* stat */
#include <unistd.h>    /* execv stat fork getpid */

#include "tester.h"    /* our own constants */

/* waiting for the child */
volatile sig_atomic_t waiting = 1;
/* binary name */
char *binary = "harness";

/* forker signalling us when it's started */
void
child_started (int signum)
{
  message(binary, "I was signalled");
  waiting = 0;
}

int
main (int argc, char **argv)
{
  pid_t child_id;
  signal(SIGUSR1, child_started);
  char msg[20]; /* for complex messages */
  
  message(binary, "started");

  child_id = fork ();
  if (child_id == 0) /* if we are the child process */
  {
    char *const childargv[1];
    execv("forker",childargv);
  }

  message(binary, "child started");

  message(binary, "waiting");
  while (waiting); /* waiting for forker to signal us */
  message(binary, "finished waiting");

  sprintf(msg, "signalling forker PID %d", child_id);
  message(binary, msg);
  kill (child_id, SIGUSR1);

  if (pmikernel() != 0)
  {
    message(binary, "not a pmi kernel, exiting");
    return 1;
  }

  return 0;
}

