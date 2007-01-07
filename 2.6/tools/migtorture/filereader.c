#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

struct stat filestat;

int main( void )
{
    int i;

    for ( i = 0; i < 10000; i ++ )
    {
	FILE* file; 
	char * buffer;


	if ( 0 != stat( "randomfile", &filestat ) )
	{
		printf(" Can't stat randomfile \n" );
		return 1;
	}

	file = fopen( "randomfile", "w");
	if (!file)
	{
		printf(" Can't open randomfile\n" );
		return 1;
	}

	buffer = (char *) malloc( filestat.st_size );

	if ( !buffer )
	{
		printf( "Can't allocate %d bytes \n", (int)filestat.st_size );
		return 1;
	}

	fread( buffer, 1, filestat.st_size, file );
	fclose( file );
	free( buffer );

	usleep( 1000000 );
    }
    return 0;
}


