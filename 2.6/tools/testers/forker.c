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
#include <string.h>    /* strcmp */

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
  signal(SIGUSR2, exit_handler);    /* for terminating */

  /* Test 1 +++ */
  message (binary, "started");
  message (binary, "SIGUSR1 --> harness");
  kill(getppid (), SIGUSR1);
  /* Test 1 --- */
  
  /* Test 2 +++ */
  message (binary, "waiting.");
  while (waiting); /* loop while waiting for signals */
  message (binary, "SIGUSR1 <-- harness");
  
  waiting = 1; /* needs to be set here because of parallelism -spook */
  
  message (binary, "forking...");
  child_id = fork ();
  if (child_id == 0) /* if we are the child */
  {
    /*
	 *  *** Child forker ***
	 */
    binary = "forker child"; /* we're now called the child */
    /* we just got forked, say hello to parent */
    message(binary, "hello, i'm alive");
	message(binary, "SIGUSR1 --> parent forker");
	kill(getppid (), SIGUSR1);

	/* wait for next section of testing */
	message(binary, "waiting for instruction from parent forker");
	/* is this next call needed? FIXME -spook */
	signal(SIGUSR1, signal_handler); /* prepare to be signalled */
	while (waiting);
    /* Test 2 --- */
	
	/* Test 3 +++--- */
	
	/* Test 4 +++ */
	/* the parent has been migrated, reply */
	message(binary, "got signal from remote parent forker, replying");
	message(binary, "SIGUSR1 --> forker parent @ remote");
	kill(getppid (), SIGUSR1);
	
	/* wait for next section where we will be migrated */
	message(binary, "waiting for instruction from parent forker");
	waiting = 1;
	while (waiting);
	/* Test 4 --- */
	
	/* Test 5 +++ */
	/* we were migrated, reply to our parent */
	message(binary, "SIGUSR1 <-- forker parent @ remote");
	message(binary, "we were migrated, saying hello to our parent");
	message(binary, "SIGUSR1 --> forker parent @ remote");
	kill(getppid (), SIGUSR1);
	message(binary, "waiting for next test");
	waiting = 1;
	while (waiting);
	/* Test 5 --- */
	
	/* Test 6 +++ */
	/* parent signalled us, reply to it */
	message(binary, "SIGUSR1 <-- forker parent @ home");
	message(binary, "parent was migrated, reply to the signal it sent us");
	message(binary, "SIGUSR1 --> forker parent @ home");
	kill(getppid (), SIGUSR1);
	message(binary, "waiting for next test");
	waiting = 1;
	while (waiting);
	/* Test 6 --- */
	
	/* Test 7 +++ */
	/* we were migrated home, let parent know we are alive */
	message(binary, "SIGUSR1 <-- forker parent @ home");
	message(binary, "we were migrated home and seem to be alive");
	message(binary, "SIGUSR1 --> forker parent @ home");
	kill(getppid (), SIGUSR1);
	message(binary, "waiting");
	waiting = 1;
	while (waiting);
	/* Test 7 --- */
	
	message(binary, "end of tests, terminating");
	return 0;
  } else /* parent forker */
  {
    /*
	 *  *** Parent forker ***
	 */
	/* Test 2 ... */
    /* child is started, wait for it to signal us */
    message(binary, "started my child, waiting for signal");
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
	/* Test 2 --- */
	
	/* Test 3 +++ */
	/* 
	 * if we arent running on a pmi kernel, harness wants to terminate us at 
	 * this point.
	 */
	/* Test 3 --- */

	/* Test 4 +++ */
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
	/* Test 4 --- */
	
	/* Test 5 +++ */
	/* harness wishes us to migrate our child */
	message(binary, "SIGUSR1 <-- harness");
    message(binary, "begin migrating our child");
    message(binary, "migration: forker child @ home -> remoteip started");
	migrate(child_id, where(getpid())); /* migrate child to our node, FIXME */
  
    /*
	 * FIXME
     * we should probably wait for the process to migrate before continuing
     * however I think this might not be the best way of doing so -spook 
     *
     * where() will return 'migrating' while it is in the process is migrating
     * and the remote ip when it is finished.
     */
    message(binary, "waiting for migration to complete");
    while (strcmp (where(child_id), where(getpid())) != 0 ); /* FIXME -spook */
	message(binary, "migration: forker child @ home -> remoteip finished");
    message(binary, "migration is complete, continuing with tests");

    /* tell child it is migrated and wait for reply */
	message(binary, "SIGUSR1 --> forker child @ remote");
	kill (child_id, SIGUSR1);
	message(binary, "waiting for reply");
	waiting = 1;
	while (waiting);
	
	/* child replied, tell harness and wait for next test */
	message(binary, "SIGUSR1 <-- forker child @ remote");
	message(binary, "child replied, tell harness");
	message(binary, "SIGUSR1 --> harness");
	kill (getppid(), SIGUSR1);
	message(binary, "waiting for next test");
	waiting = 1;
	while (waiting);
	/* Test 5 --- */
	
	/* Test 6 +++ */
	/* we have been migrated home */
	message(binary, "SIGUSR1 <-- harness");
	message(binary, "we are now at home, signal child");
	message(binary, "SIGUSR1 --> forker child @ remote");
	kill (child_id, SIGUSR1);
	message(binary, "waiting for reply");
	waiting = 1;
	while (waiting);
	
	/* child replied */
	message(binary, "SIGUSR1 <-- forker child @ remote");
	message(binary, "child replied, signalling harness");
	message(binary, "SIGUSR1 --> harness");
	kill (getppid(), SIGUSR1);
	message(binary, "waiting for next test");
	waiting = 1;
	while (waiting);
	/* Test 6 --- */
	
	/* Test 7 +++ */
	/* migrate forker child to home */
	/* harness wishes us to migrate our child */
	message(binary, "SIGUSR1 <-- harness");
    message(binary, "begin migrating our child");
	message(binary, "migration: forker child @ remoteip -> home started");
	migrate(child_id, "home"); /* migrate child to home */
  
    /*
	 * FIXME
     * we should probably wait for the process to migrate before continuing
     * however I think this might not be the best way of doing so -spook 
     *
     * where() will return 'migrating' while it is in the process is migrating
     * and 'home' when it is finished.
     */
    message(binary, "waiting for migration to complete");
    while (strcmp (where(child_id), "home") != 0); /* FIXME -spook */
    message(binary, "migration: forker child @ remoteip -> home finished");
    message(binary, "migration is complete, continuing with tests");

    /* tell child it is migrated and wait for reply */
	message(binary, "SIGUSR1 --> forker child @ home");
	kill (child_id, SIGUSR1);
	message(binary, "waiting for reply");
	waiting = 1;
	while (waiting);
	
	/* child replied, tell harness */
	message(binary, "SIGUSR1 <-- forker child @ home");
	message(binary, "SIGUSR1 --> harness");
	kill (getppid(), SIGUSR1);
    message(binary, "waiting...");
	waiting = 1;
	while (waiting);
	/* Test 7 --- */
	
	message(binary, "end of tests, terminating");
	kill(child_id, SIGTERM);
	return 0;
  }

  return 0;
}

