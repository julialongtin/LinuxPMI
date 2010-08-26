/*
GNU GPL license stuff

copyright 2010 Ashley 'spook' Wiren
*/

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

volatile sig_atomic_t waiting = 1;

void
signal_handler (int signum)
{
  printf("forker %d: I was signalled\n", (int) getpid ());
  waiting = 0; // stop waiting
}

int
main (void)
{
  signal(SIGUSR1, signal_handler);  // register the signal handler

  printf ("forker %d: started\n", (int) getpid ());
  printf ("forker %d: signalling PID %d\n", (int) getpid (), (int) getppid ());
  kill(getppid (), SIGUSR1);

  printf ("forker %d: waiting.\n", (int) getpid ());
  while (waiting); // loop while waiting for signals
  printf ("forker %d: finished waiting.\n", (int) getpid ());

  return 0;
}

