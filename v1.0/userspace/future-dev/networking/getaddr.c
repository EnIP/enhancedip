       #include <sys/types.h>
       #include <sys/socket.h>
       #include <netdb.h>
       #include <stdio.h>
       #include <stdlib.h>
       #include <unistd.h>
       #include <string.h>

       #include <netinet/in.h>
       #include <arpa/inet.h>

       #define BUF_SIZE 500

	void print_sockaddr(struct sockaddr *sa)
	{
		struct sockaddr_in *s;
		struct sockaddr_in6 *s6;
		char dst[100] = {0};

		s = (struct sockaddr_in *)sa;
		if(s->sin_family == AF_INET){
			printf("s->sin_family=%d\n", s->sin_family);
			printf("sin_port=%d\n", ntohs(s->sin_port));
			printf("sin_addr=%s\n", inet_ntoa(s->sin_addr));
		}

		if(s->sin_family == AF_INET6){
			s6=(struct sockaddr_in6 *)sa;
			printf("s->sin_family=%d\n", s6->sin6_family);
			printf("sin_port=%d\n", ntohs(s6->sin6_port));
			printf("sin_addr=%s\n", inet_ntop(AF_INET6, 
						(void *)&s6->sin6_addr.s6_addr[0], 
						dst, 100));
		}
	}

       int
       main(int argc, char *argv[])
       {
           struct addrinfo hints;
           struct addrinfo *result, *rp;
           int sfd, s, j;
           size_t len;
           ssize_t nread;
           char buf[BUF_SIZE];
	   int x = 0;

           if (argc < 3) {
               fprintf(stderr, "Usage: %s host port msg...\n", argv[0]);
               exit(EXIT_FAILURE);
           }

           /* Obtain address(es) matching host/port */

           memset(&hints, 0, sizeof(struct addrinfo));
           hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
           hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
           hints.ai_flags = 0;
           hints.ai_protocol = 0;          /* Any protocol */
           
           s = getaddrinfo(argv[1], argv[2], &hints, &result);
           if (s != 0) {
               fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
               exit(EXIT_FAILURE);
           }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or connect(2)) fails, we (close the socket
              and) try the next address. */

           for (rp = result; rp != NULL; rp = rp->ai_next) {
               sfd = socket(rp->ai_family, rp->ai_socktype,
                            rp->ai_protocol);
               if (sfd == -1)
                   continue;

		print_sockaddr(rp->ai_addr);
               if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
                   break;                  /* Success */

               close(sfd);
           }

           if (rp == NULL) {               /* No address succeeded */
               fprintf(stderr, "Could not connect\n");
               exit(EXIT_FAILURE);
           }

           freeaddrinfo(result);           /* No longer needed */

           /* Send remaining command-line arguments as separate
              datagrams, and read responses from server */

           for (j = 3; j < argc; j++) {
               len = strlen(argv[j]) + 1;
                       /* +1 for terminating null byte */

               if (len + 1 > BUF_SIZE) {
                   fprintf(stderr,
                           "Ignoring long message in argument %d\n", j);
                   continue;
               }

               if (write(sfd, argv[j], len) != len) {
                   fprintf(stderr, "partial/failed write\n");
                   exit(EXIT_FAILURE);
               }

               nread = read(sfd, buf, BUF_SIZE);
               if (nread == -1) {
                   perror("read");
                   exit(EXIT_FAILURE);
               }

               printf("Received %ld bytes: %s\n", (long) nread, buf);
           }

           exit(EXIT_SUCCESS);
       }

