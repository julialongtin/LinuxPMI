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
#include <string.h>    /* strcmp */

#include "tester.h"    /* our own constants */


volatile sig_atomic_t waiting = 1; /* wait for the child */
char *binary = "harness"; /* binary name */
char *remoteip = "192.168.168.12"; /* default remote ip */

/* forker signalling us when it's started */
void
child_started (int signum)
{
  message(binary, "I got a SIGUSR1");
  waiting = 0;
}

/*
 * harness <remoteip>
 * default ip = 192.168.168.12
 */
int
main (int argc, char **argv)
{
  pid_t child_id; /* for the first forker */
  signal(SIGUSR1, child_started);
  char msg[20]; /* for complex messages */
  
  message(binary, "started");
  if (argc != 2)
  {
    message(binary, "using the default remote ip of 192.168.168.12");
  } else
  {
    /* 
	 * FIXME
	 * Baaaaad, we should check the ip is valid and is responding
	 * purely for the sanity of people who use these tools to test -spook 
	 */
    remoteip = argv[1];
	sprintf(msg, "using the provided remote ip of %s", remoteip);
	message(binary, msg);
  }
  
  /* Test 1, forking and signalling locally */
  message(binary, "Test 1 start +++++++++++++++++++++++++++++++++++++++");
  
  child_id = fork ();
  if (child_id == 0) /* if we are the child process */
  {
    char *const childargv[1]; /* single null pointer, as per man page */
    execv("forker",childargv); /* replace ourselves with forker */
	/* this if never closes as the exec call replaces the process image */
  }

  /* forker has started, wait for it to signal us */
  message(binary, "forker started");
  message(binary, "waiting for signal");
  while (waiting); 
  
  /* forker is alive */
  message(binary, "SIGUSR1 <-- forker parent @ home");
  message(binary, "forker is alive");
  
  message(binary, "Test 1 end ---------------------------------------");
  /* Test 2, forker forks and signals child */
  message(binary, "Test 2 start +++++++++++++++++++++++++++++++++++++++");
  
  /* tell it to fork */
  message(binary, "SIGUSR1 --> forker parent @ home");
  kill (child_id, SIGUSR1);

  /* wait for forker to fork and reply */
  message(binary, "waiting for forker to fork");
  waiting = 1;
  while(waiting);
  message(binary, "SIGUSR1 <-- forker parent @ home");
  message(binary, "forker has forked, continuing...");
  
  message(binary, "Test 2 end ---------------------------------------");
  /* Test 3, test for pmi enabled kernel */
  message(binary, "Test 3 start +++++++++++++++++++++++++++++++++++++++");
  
  /* check if we can migrate */
  if (pmikernel() != 0)
  {
    message(binary, "not a pmi kernel, exiting and terminating forkers");
	message(binary, "Test 3 failed ---+++---+++---+++---+++---+++---+++---");
	message(binary, "SIGUSR2 --> forker parent @ home");
	kill (child_id, SIGUSR2); /* trigger exit_handler in forker */
    return 1;
  }
  
  message(binary, "Test 3 end ---------------------------------------");
  /* Test 4, migrate parent forker and signal */
  message(binary, "Test 4 start +++++++++++++++++++++++++++++++++++++++");
  
  /* begin migration tests */
  message(binary, "migrating the parent forker");
  message(binary, "migration: forker parent @ home -> remoteip started");
  migrate(child_id, remoteip);
  
  /*
   * FIXME
   * we should probably wait for the process to migrate before continuing
   * however I think this might not be the best way of doing so -spook 
   *
   * where() will return 'migrating' while it is in the process is migrating
   * and the remote ip when it is finished.
   */
  message(binary, "waiting for migration to complete");
  while (strcmp (where(child_id), remoteip) != 0);
  message(binary, "migration: forker parent @ home -> remoteip finished");
  message(binary, "migration is complete, continuing with test");
  
  /* signal forker to let it know migration has finished */
  message(binary, "signalling forker");
  kill (child_id, SIGUSR1);
  message(binary, "waiting for reply");
  waiting = 1;
  while (waiting);
  message(binary, "SIGUSR1 <-- forker parent @ remote");
  
  message(binary, "Test 4 end ---------------------------------------");
  /* Test 5, migrate child forker and signal */
  message(binary, "Test 5 start +++++++++++++++++++++++++++++++++++++++");
  
  /* remote forker was able to signal, migrate the other forker */
  message(binary, "asking forker to migrate its child");
  message(binary, "SIGUSR1 --> forker parent @ remote");
  kill (child_id, SIGUSR1);
  message(binary, "wait for reply");
  waiting = 1;
  while (waiting);
  
  /* remote forker parent replied, test successful */
  message(binary, "SIGUSR1 <-- forker parent @ remote");
  message(binary, "both forkers are remote and working");
  
  message(binary, "Test 5 end ---------------------------------------");
  /* Test 6, migrate parent forker to home */
  message(binary, "Test 6 start +++++++++++++++++++++++++++++++++++++++");
  
  /* migrate parent forker to home */
  message(binary, "migrating forker parent to home node");
  message(binary, "migration: forker parent @ remoteip -> home started");
  migrate(child_id, "home");

  /*
   * FIXME
   * we should probably wait for the process to migrate before continuing
   * however I think this might not be the best way of doing so -spook 
   *
   * where() will return 'migrating' while it is in the process is migrating
   * and 'home' when it is finished.
   */  
  message(binary, "waiting for migration to complete");
  while (strcmp (where(child_id), "home") != 0);
  message(binary, "migration: forker parent @ remoteip -> home finished");
  message(binary, "migration is complete, continuing with test");
  
  /* migration done, signal forker parent then wait */
  message(binary, "SIGUSR1 --> forker parent @ home");
  kill (child_id, SIGUSR1);
  message(binary, "wait for reply");
  waiting = 1;
  while (waiting);
  
  /* forker parent replied, test is complete */
  message(binary, "SIGUSR1 <-- forker parent @ home");
  message(binary, "forker parent is home and signals working");
  
  message(binary, "Test 6 end ---------------------------------------");
  /* Test 7, migrate child forker to home */
  message(binary, "Test 7 start +++++++++++++++++++++++++++++++++++++++");
  
  /* signal forker parent, so that it migrates forker child home */
  message(binary, "SIGUSR1 --> forker parent @ home");
  kill (child_id, SIGUSR1);
  message(binary, "wait for reply");
  waiting = 1;
  while (waiting);
  
  /* got a reply from forker parent, test succeeded */
  message(binary, "SIGUSR1 <-- forker parent @ home");
  message(binary, "both forkers are home and working");
  
  message(binary, "Test 7 end ---------------------------------------");
  
  message(binary, "end of tests, terminating all processes");
  message(binary, "SIGUSR2 --> forker parent");
  kill (child_id, SIGUSR2);
  return 0;
}

