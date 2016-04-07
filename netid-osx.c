#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#ifndef SA_SIZE
#define SA_SIZE(sa)                                                     \
  (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?                \
     sizeof(uint32_t)            :                                      \
     1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(uint32_t) - 1) ) )
#endif

static char *
print_lladdr(struct sockaddr_dl *sdl)
{
  static char buf[256];
  char *cp;
  int n, bufsize = sizeof (buf), p = 0;

  memset(buf, 0, sizeof (buf));
  cp = (char *)LLADDR(sdl);
  if ((n = sdl->sdl_alen) > 0) {
    while (--n >= 0)
      p += snprintf(buf + p, bufsize - p, "%x%s",
                    *cp++ & 0xff, n > 0 ? ":" : "");
  }
  return (buf);
}

static void
print_arp(struct sockaddr_dl *sdl,
          struct sockaddr_inarp *addr, struct rt_msghdr *rtm)
{
  if (sdl->sdl_alen) {
    printf("%s %s\n", print_lladdr(sdl), inet_ntoa(addr->sin_addr));
  }
}

static int listarp(void)
{
  int mib[6];
  size_t needed;
  char *lim, *buf, *newbuf, *next;
  struct rt_msghdr *rtm;
  struct sockaddr_inarp *sin2;
  struct sockaddr_dl *sdl;
  int st;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
  mib[5] = RTF_LLINFO;
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
    err(1, "route-sysctl-estimate");
  if (needed == 0)        /* empty table */
    return 0;
  buf = NULL;
  for (;;) {
    newbuf = realloc(buf, needed);
    if (!newbuf)
      return 1;
    buf = newbuf;
    st = sysctl(mib, 6, buf, &needed, NULL, 0);
    if (st == 0 || errno != ENOMEM)
      break;
    needed += needed / 8;
  }
  if (st == -1)
    err(1, "actual retrieval of routing table");
  lim = buf + needed;
  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)next;
    sin2 = (struct sockaddr_inarp *)(rtm + 1);
    sdl = (struct sockaddr_dl *)((char *)sin2 + SA_SIZE(sin2));

    print_arp(sdl, sin2, rtm);
  }
  free(buf);
  return 0;
}

int
main(int argc, char *argv[])
{
  listarp();

  return 0;
}
