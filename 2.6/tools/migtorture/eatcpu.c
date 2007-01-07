#include <stdio.h>
#include <stdlib.h>


int main( int argc, char **argv )
{
	double total = 456114157974121LL;
	double min = 0;
	double max = total;

	double square = ( min + max ) / 2.0;
	while ( total != square * square )
	{
		if ( (square*square) < total )
		{
			min = square;
		} else if (square*square > total ) {
			max = square;
		}
		square = ( min + max ) / 2;

	}
	printf("La racine carrée de %lf est %lf\n", total, square );
	return 0;
}

