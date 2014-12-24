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

char *service = "10001";

struct address {
  uint8_t hwaddr[6];
  uint8_t ipv4[4];
};

struct chunk {
  struct chunk *next;
  unsigned char type;
  union {
    void *ptr;
    unsigned int num;
    struct chunk *down;
    struct address *addr;
  } u;
};

#define NUMBER(x)               (x->u.num)
#define BUFFER(x)               (x->u.ptr)
#define HWADDR(x)               (x->u.addr->hwaddr)
#define IPV4ADDR(x)             (x->u.addr->ipv4)


typedef struct chunk message;

/* Message Types */
enum {
  DiscoverMessage = 0,
  HwAddr = 1,
  Address = 2,
  FirmwareVersion = 3,
  UpTime = 10,
  HostName = 11,
  Product = 12,
  Essid = 13,
  WirelessMode = 14,
  SystemId = 16,
};

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

int decode_chunk(struct chunk *ch, unsigned char type, unsigned char *data, unsigned int len)
{
  switch(type) {
  case SystemId:		/* 16-bit integer */
  case WirelessMode:		/*  8-bit integer */
  case UpTime:		/* 32-bit integer */
    NUMBER(ch) = get_number(data, len);
    break;

  case FirmwareVersion:	/* readable string */
  case Product:
  case HostName:
  case Essid:
    BUFFER(ch) = strndup((char *)data, len);
    break;
    
  case HwAddr:
    BUFFER(ch) = malloc(len);
    memcpy(BUFFER(ch), data, len);
    break;

  case Address:
    BUFFER(ch) = malloc(sizeof(struct address));
    memcpy(HWADDR(ch), data, 6);
    memcpy(IPV4ADDR(ch), data+6, 4);
    break;

  default:
    break;
  }

  return 0;
}

message *decode_message(unsigned char *data, unsigned int total_len)
{
  int pos = 0;
  unsigned int len;
  unsigned char type;
  struct chunk *head;
  struct chunk **cur;

  if (data[0] != 1 || data[1] != DiscoverMessage) {
    printf("oops, got id %d\n", data[1]);
    return(0);
  }

  pos = 4;
  head = malloc(sizeof(struct chunk));
  head->type = 0;
  head->u.down = 0;
  cur = &head->u.down;

  for (pos=4;pos<total_len;pos+=len) {
    type = data[pos];
    len = get_number(data + pos + 1, 2);
    pos += 3;

    (*cur) = malloc(sizeof(struct chunk));
    (*cur)->type = type;
    decode_chunk(*cur, type, data+pos, len);

    cur = &((*cur)->next);
  }

  *cur = 0;
  return head;
}

int report_chunk(struct chunk *ch)
{
  unsigned char type = ch->type;

  if (type == FirmwareVersion) {
    printf ("firmware '%s'\n", (char *)BUFFER(ch));
  } else if (type == HostName) {
    printf ("name '%s'\n", (char *)BUFFER(ch));
  } else if (type == Product) {
    printf ("board.shortname '%s'\n", (char *)BUFFER(ch));
  } else if (type == SystemId) {
    printf ("board.sysid 0x%x\n", NUMBER(ch));
  } else if (type == Essid) {
    printf ("wireless.ssid '%s'\n", (char *)BUFFER(ch));
  } else if (type == WirelessMode) {
    printf ("wmode 0x%02x\n", NUMBER(ch));
  } else if (type == Address) {
    char hwaddr[18];
    char ipv4[16];
    sprint_hwaddr(HWADDR(ch), hwaddr);
    sprint_ipv4(IPV4ADDR(ch), ipv4);
    printf ("address { hwaddr %s ipv4 %s }\n", hwaddr, ipv4);
  } else if (type == HwAddr) {
    char hwaddr[18];
    sprint_hwaddr(BUFFER(ch), hwaddr);
    printf("board.hwaddr: %s\n", hwaddr);
  } else if (type == UpTime) {
    printf ("uptime %d\n", NUMBER(ch));
  } else {
    printf("<unknown type: 0x%02x>\n", type);
  }
  return 0;
}


int report_message(message *m)
{
  struct chunk *ch;

  for (ch=m->u.down;ch;ch=ch->next) {
    report_chunk(ch);
  }

  return 0;
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

  r = getaddrinfo(name, service, &hints, &ai);

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

int main(int argc, char **argv)
{
  int r;
  int broadcast = 1;

  if (argc < 2)
    barf("need a hostname");

  if (argc >= 3) {
    service = strdup(argv[2]);
  }

  ctx.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx.sockfd < 0)
    barf(strerror(errno));

  if (lookup(argv[1]) < 0)
    barf("bad lookup");

  /* request broadcast permissions if possible */
  setsockopt(ctx.sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
  
  /* trasmit query */
  r = sendto(ctx.sockfd, query, 4, 0, (struct sockaddr *)&ctx.saddr, sizeof(ctx.saddr));
  if (r<0)
    barf(strerror(errno));

  while (collect_response()) {
    message *m;
    m = decode_message(inmsg, inlen);
    report_message(m);
    printf ("\n");
  }

  return 0;
}
