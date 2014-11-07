#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUF_SIZE 500

int main(int argc, char **argv)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s = 0;
	int sfd = 0;
	char buf[1024] = {0};
	ssize_t retval = 0;
	ssize_t counter = 0;

	if(argc < 3){
	   fprintf(stderr, "Usage: %s host port msg\n", argv[0]);
	   exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;
	s=getaddrinfo(argv[1], argv[2], &hints, &result);
	if(s!=0){
		perror("getaddrinfo");
		exit(EXIT_FAILURE);
	}

	for(rp=result;rp!=NULL;rp=rp->ai_next){
		sfd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol);
		//sfd = socket(AF_INET, rp->ai_socktype,
		//		rp->ai_protocol);
		printf("ai_family=%d ai_socktype=%d ai_protocol=%d\n",
			rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sfd == -1)
			continue;

		if(connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;	/* SUCCESS */

		close(sfd);
	}

	if(rp == NULL){
		fprintf(stderr, "Could not connect\n");
		perror("connect");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);

	write(sfd, argv[3], strlen(argv[3]));

	while(1){
		retval = read(sfd, buf, sizeof(buf));
		if(retval == 0){
			break;
		}
		else if(retval > 0){
			counter+=retval;
			printf("counter=%ld\n", counter);
		}
		else{
			perror("read");
			break;
		}
	}

	printf("transferred %ld bytes\n", counter);

	close(sfd);

	return 0;
}
