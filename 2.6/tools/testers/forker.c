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
volatile sig_atomic_t terminate = 0;
/* binary name */
char *binary = "forker";

/* for signals */
void
signal_handler (int signum)
{
  message(binary, "I got a SIGUSR1");
  waiting = 0; /* stop waiting */
}

/* for exiting */
void
exit_handler (int signum)
{
  waiting = 0;    /* stop waiting */
  terminate = 1;  /* terminate both forkers */
}

int
main (int argc, char **argv)
{
  signal(SIGUSR1, signal_handler);  /* register the signal handler */
  signal(SIGUSR2, exit_handler); /* for terminating */
  char msg[30]; /* for complex messages */
  pid_t child_id; /* for when we fork */

  message (binary, "started");
  sprintf(msg, "SIGUSR1 harness PID %d", (int) getppid ());
  message (binary, msg);
  kill(getppid (), SIGUSR1);

  message (binary, "waiting.");
  while (waiting); /* loop while waiting for signals */
  
  message (binary, "forking...");
  child_id = fork ();
  if (child_id == 0) /* if we are the child */
  {
    message(binary, "hello, i'm alive");
	sprintf(msg, "SIGUSR1 my parent forker PID %d", (int) getppid ());
	message(binary, msg);
	kill(getppid (), SIGUSR1);

	message(binary, "waiting for instruction from parent forker");
	signal(SIGUSR1, signal_handler); /* prepare to be signalled */
	waiting = 1;
	while (waiting);
	
	message(binary, "end of tests, terminating");
	return 0;
  } else /* parent forker */
  {
    message(binary, "started my child, waiting for SIGUSR1");
	signal(SIGUSR1, signal_handler);
	waiting = 1;
	while (waiting);
	message(binary, "child told me it is alive");

	message(binary, "SIGUSR1 harness");
	kill(getppid (), SIGUSR1);
	
    message(binary, "waiting for instruction from harness");
	signal(SIGUSR1, signal_handler);
	waiting = 1;
	while (waiting);
	
	if (terminate)
	{
	  message(binary, "harness wants me to TERM, sending TERM to both forkers");
	  kill(child_id, SIGTERM); /* terminate the child */
      kill(getpid (), SIGTERM); /* terminate ourselves */
	}
	
	message(binary, "end of tests, terminating");
	return 0;
  }

  return 0;
}

