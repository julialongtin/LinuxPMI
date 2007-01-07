#include <stdio.h>
#include <stdlib.h>

#define PAGE_SIZE 	4096


#define SIZE 		( PAGE_SIZE * 100 )

unsigned char buffer[SIZE] __attribute__((section(".data")));


int main(void)
{

    unsigned int i = 0;	
    unsigned char c;

    while ( 1 ) buffer[ i++ % SIZE ]  = c++;

    return 0;
}

