#include <stdio.h>
#include <sys/time.h>
#include <time.h>

typedef long long int64;

int64 compute_difference1(struct timeval before, struct timeval after)
{
	return (int64)(after.tv_sec - before.tv_sec) * 1000000 +
			(after.tv_usec - before.tv_usec);
}

int64 compute_difference2(struct timespec start, 
				    struct timespec end)
{
	
	int64 secs;  //convert seconds to nanoseconds
	int64 nsecs; //how many nanoseconds

	secs  = (end.tv_sec - start.tv_sec) * 1000000000;
	nsecs = (end.tv_nsec - start.tv_nsec);  

	return (int64)(secs + nsecs);
	
/*
	struct timespec temp;

	if((end.tv_nsec - start.tv_nsec) > 0){
		temp.tv_sec = end.tv_sec - start.tv_sec -1;
		temp.tv_nsec = 1000000000 + end.tv_nsec-start.tv_nsec;
	}else{
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}

	return temp;
*/
}

void measure_gtod(void)
{
	struct timeval before;
	struct timeval after;
	unsigned int x = 0;
	unsigned int ctr = 0;

	while(1){
		gettimeofday(&before, NULL);
		//usleep(1000000);
		gettimeofday(&after, NULL);
		printf("%lld\n", compute_difference1(before, after));
	}
}

void measure_cgt(void)
{
	struct timespec before;
	struct timespec after;
	//struct timespec result;

	while(1){
		clock_gettime(CLOCK_MONOTONIC, &before);
		//usleep(1000000);
		clock_gettime(CLOCK_MONOTONIC, &after);
		//result = compute_difference2(before, after);
		//printf("%ld %ld\n", result.tv_sec, result.tv_nsec);
		printf("%lld\n", compute_difference2(before, after));
	}
}

int main()
{
	//measure_gtod();
	measure_cgt();  ///not sure if i'm doing this one right....

}

