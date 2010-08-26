/* 
GNU GPL license stuff

copyright 2010 Ashley 'spook' Wiren
*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* waiting for the child */
volatile sig_atomic_t waiting = 1;

/* tedious number of messages */
void
message (char *msg)
{
  printf("harness %d: %s\n", (int) getpid (), msg);
}

/* read process location */
/* returns the current location */
char *
where (pid_t pid)
{
  FILE *fd;  /* this code block is horrible -spook */
  char *buffer;
  int length;
  buffer = malloc(sizeof(char)*80);
  char filename[30];
  sprintf(filename,"/proc/%d/pms/where", (int) pid);
  fd = fopen(filename,"r");
  length = (int) fread(buffer, sizeof(char), 78, fd);
  fclose(fd);
  return buffer;
}

/* migrates a process */
void
migrate (pid_t pid, char *location)
{
  FILE *fd;  /* this code block is also horrible -spook */
  char filename[30];
  sprintf(filename,"/proc/%d/pms/where", (int) pid);
  fd = fopen(filename,"w");
  fwrite(location,sizeof(char),15,fd);
  fclose(fd);
}

/* forker signalling us when it's started */
void
child_started (int signum)
{
  message("I was signalled");
  waiting = 0;
}

int
main (int argc, char **argv)
{
  pid_t child_id;
  signal(SIGUSR1, child_started);

  message("started");

  child_id = fork ();
  if (child_id == 0) // if we are the child process
  {
    char *const childargv[1];
    execv("forker",childargv);
  }

  message("child started");

  message("waiting");
  while (waiting); // waiting for forker to signal us
  message("finished waiting");

  printf("harness %d: signalling forker PID %d\n", (int) getpid (),child_id);
  kill (child_id, SIGUSR1);

  return 0;
}

