/* 
 * Parse a Ubiquity discovery packet
 */
#include <arpa/inet.h>
#include <malloc.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

void barf(char *s)
{
    printf("error: %s\n", s);
    exit(EXIT_FAILURE);
}


void spaces(int i)
{
  while (i--)
    fputc(' ', stdout);
}

/* void dump_chunk(unsigned char *chunk, int len, char *str) */
/* { */
/*   int i; */
/*   for (i=0;i<len;i++) { */
/*     if (i!=0) */
/*       fputc(' ', stdout); */
/*     sprintf ("%02X", chunk[i]); */
/*   } */
/* } */

void sprint_hwaddr(unsigned char *b, char *str)
{
  int i;
  for (i=0;i<6;i++)
    sprintf (str + 3*i, "%02x:", b[i]);

  str[17] = 0;
}

void sprint_ipv4(unsigned char *b, char *str)
{
  inet_ntop(AF_INET, b, str, 20);
}

unsigned int get_number(unsigned char *b, int len)
{
  unsigned int n;
  int i;

  n = 0;
  for (i=0;i<len;i++) {
    n <<= 8;
    n |= b[i];
  }

  return n;
}

int report_chunk(int depth, unsigned char *chunk, unsigned int total_len)
{
  unsigned int len;
  unsigned char type;
  char *str;
  int pos = 0;
  
  while (pos < total_len) {
    type = chunk[pos];
    len = get_number(chunk + pos + 1, 2);
    pos += 3;

    spaces(depth);
    if (type == 0) {
      printf ("discover-message (len %d)\n", len);
      report_chunk(depth+2, chunk+pos, len);
    } else if (type == 0x03) {
      str = strndup(chunk+pos, len);
      printf ("firmware '%s'\n", str);
      free(str);
    } else if (type == 0x0b) {
      str = strndup(chunk+pos, len);
      printf ("name '%s'\n", str);
      free(str);
    } else if (type == 0x0c) {
      str = strndup(chunk+pos, len);
      printf ("board.shortname '%s'\n", str);
      free(str);
    } else if (type == 0x10) {
      unsigned int sysid;
      sysid = get_number(chunk+pos, len);
      printf ("board.sysid 0x%x\n", sysid);
    } else if (type == 0x0d) {
      str = strndup(chunk+pos, len);
      printf ("wireless.ssid '%s'\n", str);
      free(str);
    } else if (type == 0x0e) {
      printf ("wmode 0x%02x\n", chunk[pos]);
    } else if (type == 0x02) {
      char hwaddr[18];
      char ipv4[16];
      sprint_hwaddr(chunk+pos, hwaddr);
      sprint_ipv4(chunk+pos+6, ipv4);
      printf ("address: hwaddr %s ipv4 %s\n", hwaddr, ipv4);
    } else if (type == 0x01) {
      printf ("board.hwaddr ");
      char hwaddr[18];
      sprint_hwaddr(chunk+pos, hwaddr);
      printf("hwaddr: %s\n", hwaddr);
    } else if (type == 0x0a) {
      unsigned int uptime;
      uptime = get_number(chunk+pos, 4);
      printf ("uptime %d\n",uptime);      
    } else {
      printf("<unknown type: 0x%02x>\n", type);
    }
    pos += len;
  }
}
int report_msg(unsigned char *msg, int total_len)
{
  unsigned char magic;

  magic = msg[0];
  msg++;

  if (magic != 1) {
    printf ("oops: magic is not 1!\n");
  }
  report_chunk(0, msg, total_len-1);
}

struct {
  int sockfd;
  struct sockaddr_in saddr;
} ctx;

/*                        version/magic  type    length            ? */
unsigned char query[] = { 0x01,          0x00,   0x00, 0x00 };


int lookup(char *name)
{
  struct addrinfo hints;
  char addrstr[128];
  struct sockaddr_in *sa;
  struct addrinfo *ai;
  int r;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  r = getaddrinfo(name, "10001", &hints, &ai);

  if (r<0)
    barf(strerror(errno));

  /* grab the first address */
  sa = (struct sockaddr_in *)ai->ai_addr;
  inet_ntop(AF_INET, &sa->sin_addr, addrstr, ai->ai_addrlen);
  bcopy(ai->ai_addr, &ctx.saddr, ai->ai_addrlen);

  freeaddrinfo(ai);

  return r;
}


unsigned char inmsg[4096];
int inlen;

int collect_response()
{
  struct sockaddr_in sa;
  socklen_t sl;
  fd_set rfds;
  struct timeval tv;
  int retval;

  FD_ZERO(&rfds);
  FD_SET(ctx.sockfd, &rfds);

  tv.tv_sec = 2;
  tv.tv_usec = 0;

  retval = select(ctx.sockfd+1, &rfds, 0, 0, &tv);
  if (retval)
    inlen = recvfrom(ctx.sockfd, inmsg, 4096, 0, (struct sockaddr *)&sa, &sl);

  return retval;
}

main(int argc, char **argv)
{
  int r;

  if (argc < 2)
    barf("need a hostname");

  if (argc >= 3) {
    unsigned char t;
    sscanf(argv[2], "%x", &t);
    printf ("doing type 0x%x\n", t);
    query[1]=t;
  }

  ctx.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx.sockfd < 0)
    barf(strerror(errno));


  if (lookup(argv[1]) < 0)
    barf("bad lookup");

  /* trasmit query */
  r = sendto(ctx.sockfd, query, 4, 0, (struct sockaddr *)&ctx.saddr, sizeof(ctx.saddr));
  if (r<0)
    barf(strerror(errno));

  while (collect_response())
	 report_msg(inmsg, inlen);
}
