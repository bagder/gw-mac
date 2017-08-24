#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>
#include <ifaddrs.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

  buf[0] = 0;
  cp = (char *)LLADDR(sdl);
  n = sdl->sdl_alen;
  if (n > 0) {
    while (--n >= 0)
      p += snprintf(&buf[p], bufsize - p, "%02x%s",
                    *cp++ & 0xff, n > 0 ? ":" : "");
  }
  return buf;
}

static int show(struct sockaddr_dl *sdl,
                struct sockaddr_inarp *addr,
                struct rt_msghdr *rtm,
                char *ip)
{
  if (sdl->sdl_alen) {
    if(!strcmp(inet_ntoa(addr->sin_addr), ip)) {
      printf("id: %s\n", print_lladdr(sdl));
      return 1; /* done! */
    }
  }
  return 0; /* continue */
}

static int getarp(char *ip)
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

    if(show(sdl, sin2, rtm, ip))
      break;
  }
  free(buf);
  return 0;
}


static void routingtable(char *gw)
{
  size_t needed;
  int mib[6];
  char *buf;
  struct rt_msghdr *rtm;
  struct sockaddr *sa;
  struct sockaddr_in *sockin;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = 0;
  mib[4] = NET_RT_DUMP;
  mib[5] = 0;
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
    err(1, "sysctl: net.route.0.0.dump estimate");
  }

  if ((buf = (char *)malloc(needed)) == NULL) {
    errx(2, "malloc(%lu)", (unsigned long)needed);
  }
  if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
    err(1, "sysctl: net.route.0.0.dump");
  }

  rtm = (struct rt_msghdr *)buf;
  sa = (struct sockaddr *)(rtm + 1);
  sa = (struct sockaddr *)(SA_SIZE(sa) + (char *)sa);
  sockin = (struct sockaddr_in *)sa;
  inet_ntop(AF_INET, &sockin->sin_addr.s_addr, gw, MAXHOSTNAMELEN-1);

  free(buf);
}

/* IPv6 address scopes. */
#define IPV6_SCOPE_GLOBAL       0       /* Global scope. */
#define IPV6_SCOPE_LINKLOCAL    1       /* Link-local scope. */
#define IPV6_SCOPE_SITELOCAL    2       /* Site-local scope (deprecated). */
#define IPV6_SCOPE_UNIQUELOCAL  3       /* Unique local */
#define IPV6_SCOPE_NODELOCAL    4       /* Loopback. */

#if 0
static const char *scope2str(int scope)
{
  switch(scope) {
  case IPV6_SCOPE_LINKLOCAL:
    return "link-local";
  case IPV6_SCOPE_SITELOCAL:
    return "site-local";
  case IPV6_SCOPE_UNIQUELOCAL:
    return "unique-local";
  case IPV6_SCOPE_NODELOCAL:
    return "node-local";
  default:
    return "global";
  }
}
#endif

/* Return the scope of the given address. */
static int ipv6_scope(const struct sockaddr_in6 *sa6)
{
  if(sa6->sin6_family == AF_INET6) {
    const unsigned char *b = sa6->sin6_addr.s6_addr;
    unsigned short w = (unsigned short) ((b[0] << 8) | b[1]);

    if((b[0] & 0xFE) == 0xFC) /* Handle ULAs */
      return IPV6_SCOPE_UNIQUELOCAL;
    switch(w & 0xFFC0) {
    case 0xFE80:
      return IPV6_SCOPE_LINKLOCAL;
    case 0xFEC0:
      return IPV6_SCOPE_SITELOCAL;
    case 0x0000:
      w = b[1] | b[2] | b[3] | b[4] | b[5] | b[6] | b[7] | b[8] | b[9] |
        b[10] | b[11] | b[12] | b[13] | b[14];
      if(w || b[15] != 0x01)
        break;
      return IPV6_SCOPE_NODELOCAL;
    default:
      break;
    }
  }

  return IPV6_SCOPE_GLOBAL;
}

/* code inspired by mac osx's ifconfig:
   https://opensource.apple.com/source/network_cmds/network_cmds-511/ifconfig.tproj/ifconfig.c.auto.html */
static int
ipv6_prefix(void *val, int size)
{
  unsigned char *name = (unsigned char *)val;
  int byte, bit, plen = 0;

  for (byte = 0; byte < size; byte++, plen += 8)
    if (name[byte] != 0xff)
      break;
  if (byte == size)
    return (plen);
  for (bit = 7; bit != 0; bit--, plen++)
    if (!(name[byte] & (1 << bit)))
      break;
  for (; bit != 0; bit--)
    if (name[byte] & (1 << bit))
      return(0);
  byte++;
  for (; byte < size; byte++)
    if (name[byte])
      return(0);
  return (plen);
}

#define MAX_PRFS 8

static void ipv6netid(void)
{
  struct ifaddrs *ifap;
  struct in6_addr pr[MAX_PRFS];
  int gl = 0;

  memset(pr, 0, sizeof(pr));
  if (!getifaddrs(&ifap)) {
    struct ifaddrs *ifa;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == NULL)
        continue;
      if ((AF_INET6 == ifa->ifa_addr->sa_family) &&
          !(ifa->ifa_flags & (IFF_POINTOPOINT|IFF_LOOPBACK))) {
        /* only IPv6 interfaces that aren't pointtopoint or loopback */
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *)ifa->ifa_netmask;
        if (sin) {
          char addr_buf[128];
          int scope;
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
          scope = ipv6_scope(sin6);
          if(scope == IPV6_SCOPE_GLOBAL) {
            /* only global scope */
            int prefix;
            inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf,
                      sizeof(addr_buf));
            prefix = ipv6_prefix(&sin->sin6_addr, sizeof(struct in6_addr));
            if(prefix && (prefix  < 128)) {
              unsigned char *p = (unsigned char *)&sin6->sin6_addr;
              int i;
              int match = 0;
#if 0
              /* a non-zero prefix that is smaller than 128 */
              printf("Name: %s %s (%s)\n", ifa->ifa_name, scope2str(scope), addr_buf);
              printf("  prefix %d bits:", prefix);
#endif
              /* check if prefix was already found */
              for(i=0; i<gl; i++) {
                if(!memcmp(&pr[i], p, prefix/8)) {
                  /* a match */
                  match = 1;
                  break;
                }
              }
              if(match)
                /* already found */
                continue;
              memcpy(&pr[gl], p, prefix/8);
              printf("id6: ");
              for(i=0; i<prefix/8; i++, p++) {
                printf("%s%02x", i?":":"", *p);
              }
              puts("");
              gl++;
              if(gl == MAX_PRFS) {
                /* reach maximum number of prefixes */
                break;
              }
            }
          }
        }
      }
    }
    freeifaddrs(ifap);
  }
  if(!gl) {
    printf("No IPv6 netid found\n");
  }
}

int main(void)
{
  char defaultgw[MAXHOSTNAMELEN];
  routingtable(defaultgw);
  getarp(defaultgw);
  ipv6netid();
  return 0;
}
