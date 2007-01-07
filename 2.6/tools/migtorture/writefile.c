#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main( void )
{
    int i;

    for ( i = 0; i < 1000; i ++ )
    {
	FILE* file; 
	file = fopen( "test.log", "w");
	if ( !file )
	{
	    printf(" Can't open file ... \n" );
	    return 1;
	}
	int j;
	for ( j = 0; j < 10; j ++ )
	{
	    fprintf(file, "I am writing for the %d time !! \n", 10*i+j);
	}
	fclose( file );
	usleep( 1000000 );
    }
    return 0;
}


