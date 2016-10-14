#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/* IPv4 routes */

#define PROC_ROUTE "/proc/net/route"
#define PROC_ARP   "/proc/net/arp"
#define PROC_IF_INET6 "/proc/net/if_inet6"

int getarp(uint32_t ip)
{
  int found = 1;
  char searchfor[16];
  sprintf(searchfor, "%d.%d.%d.%d",
          ip & 0xff,
          (ip >> 8) & 0xff,
          (ip >> 16) & 0xff,
          ip >> 24);

  //printf("search for %s\n", searchfor);

  FILE *farp = fopen(PROC_ARP, "r");
  if (farp) {
    char buffer[512];
    char *l = fgets(buffer, sizeof(buffer), farp);
    while (l) {
      /* skip the title line  */
      l = fgets(buffer, sizeof(buffer), farp);
      if (l) {
        int p[4];
        char type[16];
        char flags[16];
        char hw[32];
        if(7 == sscanf(buffer, "%u.%u.%u.%u %15s %15s %31s",
                       &p[0], &p[1], &p[2], &p[3],
                       type, flags, hw)) {
          uint32_t searchip = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
          if(ip == searchip) {
            printf("id: %s\n", hw);
            found = 0;
            break;
          }
        }
      }
    }
    fclose(farp);
  }
  return found;
}

uint32_t getroute(void)
{
  uint32_t gw = 0;
  FILE *froute = fopen(PROC_ROUTE, "r");
  if (froute) {
    char buffer[512];
    char *l = fgets(buffer, sizeof(buffer), froute);
    if (l) {
      /* skip the title line  */
      while(l) {
        char interf[32];
        uint32_t dest;
        uint32_t gateway;
        l = fgets(buffer, sizeof(buffer), froute);
        if (l) {
          int val = sscanf(buffer, "%31s %x %x", interf, &dest, &gateway);
          if(3 == val) {
            if (!dest) {
              //printf("Default gateway is %s/%08x\n", interf, gateway);
              gw = gateway;
              break;
            }
          }
        }
      }
    }
    fclose(froute);
  }
  return gw;
}

#define GLOBAL 0x00 /* 0x20 for debugging, 0x00 for reality */

void getprefix(void)
{
  FILE *ifs = fopen(PROC_IF_INET6, "r");
  if (ifs) {
    char buffer[512];
    char ip6[40];
    int devnum;
    int preflen;
    int scope;
    int flags;
    char name[40];

    char *l = fgets(buffer, sizeof(buffer), ifs);
    /* 2a001a28120000090000000000000002 02 40 00 80   eth0 */
    /* +------------------------------+ ++ ++ ++ ++   ++
     * |                                |  |  |  |    |
     * 1                                2  3  4  5    6
     *
     * 1. IPv6 address displayed in 32 hexadecimal chars without colons as
     *    separator
     *
     * 2. Netlink device number (interface index) in hexadecimal.
     *
     * 3. Prefix length in hexadecimal number of bits
     *
     * 4. Scope value (see kernel source include/net/ipv6.h and
     *    net/ipv6/addrconf.c for more)
     *
     * 5. Interface flags (see include/linux/rtnetlink.h and net/ipv6/addrconf.c
     *    for more)
     *
     * 6. Device name
     */
    while(l) {
      if(6 == sscanf(buffer, "%32[0-9a-f] %02x %02x %02x %02x %31s",
                     ip6, &devnum, &preflen, &scope, &flags, name)) {
        if(scope == GLOBAL) {
          unsigned char id6[33];
          int i, j;
          int bits;
          memset(id6, 0, sizeof(id6));
#if 0
          printf("IPv6: %s matched, scope = %d, %d bits prefix\n",
                 name, scope, preflen);
#endif
          for(bits=preflen, i=0; bits>0; bits-=8, i++) {
            char buf[3];
            long val;
            int mask;
            int maskit[]={0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
            buf[0]=ip6[i*2];
            buf[1]=ip6[i*2+1];
            buf[2]=0;
            /* convert from hex */
            val = strtol(buf, NULL, 16);
            mask = ( bits >= 8 ) ? 0xff : maskit[bits];
            id6[i]=(unsigned char)val&mask;
          }
          printf("id6: ");
          for(j=0; j<i; j++)
            printf("%s%02x", j?":":"", id6[j]);
          printf("\n");
        }
      }

      l = fgets(buffer, sizeof(buffer), ifs);
    }
    fclose(ifs);
  }

}

int main(void)
{
  uint32_t gw = getroute();
  int rc = 0;
  if(gw) {
    if(getarp(gw)) {
      puts("gw not in ARP table");
      rc = 1;
    }
  }
  else {
    puts("default gateway not found");
    rc = 2;
  }

  if(1) {
    /* IPv4 check failed, check IPv6 global scope net prefix */
    getprefix();
  }
}
