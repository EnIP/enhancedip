#include <stdio.h>
#include <sys/time.h>


int main()
{
	struct timeval before;
	struct timeval after;

	gettimeofday(&before, NULL);
	sleep(5);
	gettimeofday(&after, NULL);

	printf("%ld\n", after.tv_sec - before.tv_sec);

	return 0;

}

