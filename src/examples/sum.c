/* Added system call. 
(1) int pibonacci (int n)
(2) int sum_of_four_integers (int a, int b, int c, int d)
*/

#include <stdio.h>
#include <string.h>
#include <syscall.h>
#define MAX_LEN 100

int str_to_int(const char *str);
int exp_my(int);

// echo.c를 참조
int
main (int argc, char **argv)
{
	int i;
	// 1. Casting argv[1]~argv[4] to integer.
	int num[4];
	for (i = 1; i < argc; i++){
		//ASCII to integer.(ASCII 48 = integer 0)
		num[i-1] = str_to_int(argv[i]);
	}

	// 2. Using argv[0], call pibonacci.
	wait(pibonacci(num[0]));	// if argv[0]==5, call pibonacci(5) 

	// 3. Call sum_of_four_integers.
	wait(sum_of_four_integers(num[0], num[1], num[2], num[3]));
	return EXIT_SUCCESS;
}

int
exp_my(int exponent){
	int result = 1;
	int i;
	for(i=0;i<exponent;i++)
		result = result * 10;
	return result;
}
int
str_to_int(const char *str){
	size_t i;
	int integer=0;
	size_t length;
	length = strnlen(str, MAX_LEN);
	for(i=0; i<length; i++){
		integer = integer + (str[(length-1)-i]-48)*exp_my(i);
	}
	return integer;
}
