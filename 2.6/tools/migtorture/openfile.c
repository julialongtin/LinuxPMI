#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main( void )
{
    int i;

    for ( i = 0; i < 10000; i ++ )
    {
	FILE* file; 
	file = fopen( "test.log", "w");
	usleep( 1000000 );
	fclose( file );
	usleep( 1000000 );
    }
    printf(" Tired of speaking :( \n");
    return 0;
}


