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
#include <stdio.h>     /* printf sprintf */
#include <stdlib.h>    /* malloc free */
#include <sys/types.h> /* kill getpid stat */
#include <sys/stat.h>  /* stat */
#include <unistd.h>    /* stat fork getpid */

#include "tester.h"    /* our own constants */

/* waiting for signals */
volatile sig_atomic_t waiting = 1;
/* binary name */
char *binary = "forker";

void
signal_handler (int signum)
{
  message(binary, "I was signalled");
  waiting = 0; /* stop waiting */
}

int
main (int argc, char **argv)
{
  signal(SIGUSR1, signal_handler);  /* register the signal handler */
  char msg[20]; /* for complex messages */

  message (binary, "started");
  sprintf(msg, "signalling harness PID %d", (int) getppid ());
  message (binary, msg);
  kill(getppid (), SIGUSR1);

  message (binary, "waiting.");
  while (waiting); /* loop while waiting for signals */
  message (binary, "finished waiting.");

  return 0;
}

