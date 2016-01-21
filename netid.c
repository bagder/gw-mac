#include <stdio.h>
#include <string.h>
#include <inttypes.h>

/* IPv4 routes */

#define PROC_ROUTE "/proc/net/route"
#define PROC_ARP   "/proc/net/arp"

void getarp(uint32_t ip)
{
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
          }
        }
      }
    }
    fclose(farp);
  }
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

int main(void)
{
  uint32_t gw = getroute();
  getarp(gw);
}
