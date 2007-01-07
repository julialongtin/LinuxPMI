#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main( void )
{
    int i;
    for ( i = 0; i < 1000; i ++ )
    {
	int j;
	for ( j = 0; j < 10; j ++ )
	{
	    printf( "I am speaking for the %d time !! \n", 10*i+j);
	}
	usleep( 1000000 );
    }
    printf(" Tired of speaking :( \n");
    return 0;
}


