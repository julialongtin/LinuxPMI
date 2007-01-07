#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MEMSIZE (50*1024*1024)

int main( void )
{
    int i;
    for ( i = 0; i < 1000; i ++ )
    {
	int j;
	char* buffer = NULL;
	
	buffer = (char *) malloc( MEMSIZE );
	if (!buffer) 
	{
		printf( "Unable to get some memory T_T\n" );
		return 1;
	}
	for ( j = 0; j < MEMSIZE ; j++)
	{
		buffer[j] = (char) j & 0xff;
	}
	usleep( 1000000 );
	free(buffer);
    }
    return 0;
}


