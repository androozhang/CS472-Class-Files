#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include "http.h"

//---------------------------------------------------------------------------------
// TODO:  Documentation
//
// Note that this module includes a number of helper functions to support this
// assignment.  YOU DO NOT NEED TO MODIFY ANY OF THIS CODE.  What you need to do
// is to appropriately document the socket_connect(), get_http_header_len(), and
// get_http_content_len() functions. 
//
// NOTE:  I am not looking for a line-by-line set of comments.  I am looking for 
//        a comment block at the top of each function that clearly highlights you
//        understanding about how the function works and that you researched the
//        function calls that I used.  You may (and likely should) add additional
//        comments within the function body itself highlighting key aspects of 
//        what is going on.
//
// There is also an optional extra credit activity at the end of this function. If
// you partake, you need to rewrite the body of this function with a more optimal 
// implementation. See the directions for this if you want to take on the extra
// credit. 
//--------------------------------------------------------------------------------

char *strcasestr(const char *s, const char *find)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		c = tolower((unsigned char)c);
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while ((char)tolower((unsigned char)sc) != c);
		} while (strncasecmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

char *strnstr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == '\0' || slen-- < 1)
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

/*
socket_connect connects to a tcp socket using a host and port number.
It first gets the ip of the host to configure a socket address struct along with the port passed in.
Then, it to create a TCP socket and attempt a connection.

Input: a pointer to hostname and an unsigned integer for port number
Output: file descriptor for the socket open or a negative number for any errors
        -1 if socket creation fails
        -2 if host is invalid
*/
int socket_connect(const char *host, uint16_t port){
    struct hostent *hp; // This is the struct that will hold the info related to the hostname such as IP Address and address name 
    struct sockaddr_in addr;
    int sock;

    // Gets IP address, address length and other information based on the host
    // Also handles any error on invalid host
    if((hp = gethostbyname(host)) == NULL){
		herror("gethostbyname");
		return -2;
	}
    
    // Creates socket address struct and a TCP socket
	bcopy(hp->h_addr_list[0], &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET; 
	sock = socket(PF_INET, SOCK_STREAM, 0); // Makes tcp socket using SOCK_STREAM
	
	if(sock == -1){
		perror("socket");
		return -1;
	}

    // Attempts to connect to the socket along with some error handling
    if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
		perror("connect");
		close(sock);
        return -1;
	}

    // Return file descriptor for the socket
    return sock;
}


/*
get_http_header_len gets the length of the header of a http response.
It first finds the first occurence of \r\n\r\n which signifies the header of a HTTP_HEADER.
It then returns the address of the HTTP_HEADER_END substracted by the address of the HTTP_BUFFER so we can 
find the length of the HEADER. It also accounts for the length of the delimiter for HTTP_HEADER_END

Input: the buffer of the http response and the length of it
Output: length of the header in int or a negative int for any errors
        -1 if it couldn't find the end of the http header
*/
int get_http_header_len(char *http_buff, int http_buff_len){
    char *end_ptr;
    int header_len = 0;

    // Finds the first occurence of HTTP_HEADER_END in the buffer
    end_ptr = strnstr(http_buff,HTTP_HEADER_END,http_buff_len);

    // Error handling
    if (end_ptr == NULL) {
        fprintf(stderr, "Could not find the end of the HTTP header\n");
        return -1;
    }

    // Substract the two memory addresses so that we can find the length of the header
    header_len = (end_ptr - http_buff) + strlen(HTTP_HEADER_END);

    return header_len;
}


/*
get_http_content_len gets the length of the content of a http response.
It first gets the address of the http buffer along with the address of where the header ends.
Next, while the address of the http buffer is less then the header's address, it will try to find 
the key value Content-Length in the header. If it can't find it, it will go to the next key-value pair in the header.

Input: the buffer of the http response and the length of it
Output: length of the content in int
*/
int get_http_content_len(char *http_buff, int http_header_len){
    char header_line[MAX_HEADER_LINE]; // This is used to store the key-value pair as we look through the header

    char *next_header_line = http_buff;
    char *end_header_buff = http_buff + http_header_len;

    while (next_header_line < end_header_buff){
        // Reset the header_line so that we can populate with the next key-value pair in header
        bzero(header_line,sizeof(header_line));
        // Populates the header_line with the next key_value using the address of next_header_line
        sscanf(next_header_line,"%[^\r\n]s", header_line);

        // Checks if the current key:value pair has Content-Length
        char *isCLHeader = strcasestr(header_line,CL_HEADER);
        if(isCLHeader != NULL){
            // Find the address in the string where the : delimiter is
            char *header_value_start = strchr(header_line, HTTP_HEADER_DELIM);
            if (header_value_start != NULL){
                // Skips past the delimiter and convert the length string to a integer
                char *header_value = header_value_start + 1;
                int content_len = atoi(header_value);
                return content_len;
            }
        }
        // Add the length of header_line to next_header_line so that the address points to the next key:value pair
        next_header_line += strlen(header_line) + strlen(HTTP_HEADER_EOL);
    }
    fprintf(stderr,"Did not find content length\n");
    return 0;
}

//This function just prints the header, it might be helpful for your debugging
//You dont need to document this or do anything with it, its self explanitory. :-)
void print_header(char *http_buff, int http_header_len){
    fprintf(stdout, "%.*s\n",http_header_len,http_buff);
}

//--------------------------------------------------------------------------------------
//EXTRA CREDIT - 10 pts - READ BELOW
//
// Implement a function that processes the header in one pass to figure out BOTH the
// header length and the content length.  I provided an implementation below just to 
// highlight what I DONT WANT, in that we are making 2 passes over the buffer to determine
// the header and content length.
//
// To get extra credit, you must process the buffer ONCE getting both the header and content
// length.  Note that you are also free to change the function signature, or use the one I have
// that is passing both of the values back via pointers.  If you change the interface dont forget
// to change the signature in the http.h header file :-).  You also need to update client-ka.c to 
// use this function to get full extra credit. 
//--------------------------------------------------------------------------------------
int process_http_header(char *http_buff, int http_buff_len, int *header_len, int *content_len){
    int h_len, c_len = 0;
    h_len = get_http_header_len(http_buff, http_buff_len);
    if (h_len < 0) {
        *header_len = 0;
        *content_len = 0;
        return -1;
    }
    c_len = get_http_content_len(http_buff, http_buff_len);
    if (c_len < 0) {
        *header_len = 0;
        *content_len = 0;
        return -1;
    }

    *header_len = h_len;
    *content_len = c_len;
    return 0; //success
}