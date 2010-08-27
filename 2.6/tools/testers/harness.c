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
	 * Baaaaad, we should check the ip is valid and is responding
	 * purely for the sanity of people who use these tools to test -spook 
	 */
    remoteip = argv[1];
	sprintf(msg, "using the provided remote ip of %s", remoteip);
	message(binary, msg);
  }
	
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
  
  /* forker is alive, tell it to fork */
  message(binary, "SIGUSR1 <-- forker parent @ home");
  message(binary, "forker is alive");
  message(binary, "SIGUSR1 --> forker parent @ home");
  kill (child_id, SIGUSR1);

  /* wait for forker to fork and reply */
  message(binary, "waiting for forker to fork");
  waiting = 1;
  while(waiting);
  message(binary, "SIGUSR1 <-- forker parent @ home");
  message(binary, "forker has forked, continuing...");
  
  /* check if we can migrate */
  if (pmikernel() != 0)
  {
    message(binary, "not a pmi kernel, exiting and terminating forkers");
	message(binary, "SIGUSR2 --> forker parent @ home");
	kill (child_id, SIGUSR2); /* trigger exit_handler in forker */
    return 1;
  }
  
  /* begin migration tests */
  message(binary, "migrating the parent forker");
  migrate(child_id, remoteip);
  
  /*
   * we should probably wait for the process to migrate before continuing
   * however I think this might not be the best way of doing so -spook 
   *
   * where() will return 'migrating' while it is in the process is migrating
   * and the remote ip when it is finished.
   */
  message(binary, "waiting for migration to complete");
  while (where (child_id) != remoteip);
  message(binary, "migration is complete, continuing with tests");
  
  /* signal forker to let it know migration has finished */
  message(binary, "signalling forker");
  kill (child_id, SIGUSR1);
  message(binary, "waiting for reply");
  waiting = 1;
  while (waiting);
  
  return 0;
}

