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
char *binary = "forker";  /* binary name */
pid_t child_id; /* for when we fork */

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
  message(binary, "SIGUSR2 <-- harness");
  message(binary, "harness requests me to TERM, sending TERM to both forkers");
  kill(child_id, SIGTERM); /* terminate the child */
  kill(getpid (), SIGTERM); /* terminate ourselves */
}

int
main (int argc, char **argv)
{
  signal(SIGUSR1, signal_handler);  /* register the signal handler */
  signal(SIGUSR2, exit_handler); /* for terminating */

  message (binary, "started");
  message (binary, "SIGUSR1 --> harness");
  kill(getppid (), SIGUSR1);

  message (binary, "waiting.");
  while (waiting); /* loop while waiting for signals */
  message (binary, "SIGUSR1 <-- harness");
  
  message (binary, "forking...");
  child_id = fork ();
  if (child_id == 0) /* if we are the child */
  {
    binary = "forker child"; /* we're now called the child */
    /* we just got forked, say hello to parent */
    message(binary, "hello, i'm alive");
	message(binary, "SIGUSR1 --> parent forker");
	kill(getppid (), SIGUSR1);

	/* wait for next section of testing */
	message(binary, "waiting for instruction from parent forker");
	signal(SIGUSR1, signal_handler); /* prepare to be signalled */
	waiting = 1;
	while (waiting);
	
	/* the parent has been migrated, reply */
	message(binary, "got signal from remote parent forker, replying");
	message(binary, "SIGUSR1 --> forker parent @ remote");
	kill(getppid (), SIGUSR1);
	
	/* wait for next section where we will be migrated */
	message(binary, "waiting for instruction from parent forker");
	waiting = 1;
	while (waiting);
	
	message(binary, "end of tests, terminating");
	return 0;
  } else /* parent forker */
  {
    /* child is started, wait for it to signal us */
    message(binary, "started my child, waiting for signal");
	signal(SIGUSR1, signal_handler);
	waiting = 1;
	while (waiting);
	
	/* child is alive, tell the harness to continue */
	message(binary, "SIGUSR1 <-- forker child");
	message(binary, "child is alive, continuing...");
	message(binary, "SIGUSR1 --> harness");
	kill(getppid (), SIGUSR1);
	
	/* wait for harness to migrate us if able */
    message(binary, "waiting for harness to migrate us");
	signal(SIGUSR1, signal_handler);
	waiting = 1;
	while (waiting);
	
	/* 
	 * if we arent running on a pmi kernel, harness wants to terminate us at 
	 * this point.
	 */

	/* we have been migrated */
	message(binary, "SIGUSR1 <-- harness");
	message(binary, "we have migrated, continuing...");
    message(binary, "SIGUSR1 --> forker child @ home");
	kill (child_id, SIGUSR1);
	
	/* wait for child to reply */
	message(binary, "waiting for reply");
	waiting = 1;
	while (waiting);
	
	/* child replied, tell harness and wait for next section */
	message(binary, "SIGUSR1 <-- forker child @ home");
	message(binary, "SIGUSR1 --> harness");
	kill (getppid (), SIGUSR1);
	message(binary, "waiting for next instruction");
	waiting = 1;
	while (waiting);
	
	message(binary, "end of tests, terminating");
	return 0;
  }

  return 0;
}

