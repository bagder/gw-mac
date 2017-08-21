#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <iphlpapi.h>
#include <iptypes.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static BOOL macaddr(BYTE addr[], DWORD len, char str[])
{
  DWORD i;
  str[0] = '\0';
  if (addr == NULL || !len)
    return FALSE;

  for (i = 0; i < len; i++)
    sprintf_s(str + (i * 3), sizeof(str + (i * 3)),
              "%02x%s", addr[i], (i == len-1) ? "": ":");

  return TRUE;
}

static int arplist(char *gateway)
{
  PMIB_IPNETTABLE pIpNetTable = NULL;

  // query for buffer size needed
  DWORD dwActualSize = 0;
  DWORD status = GetIpNetTable(pIpNetTable, &dwActualSize, FALSE);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    /* the expected route, now with a known buffer size */

    pIpNetTable = (PMIB_IPNETTABLE) malloc(dwActualSize);
    status = GetIpNetTable(pIpNetTable, &dwActualSize, FALSE);

    if (status == NO_ERROR) {
      char szPrintablePhysAddr[256];
      char szIpAddr[128];
      struct in_addr inadTmp;
      DWORD dwCurrIndex;
      char *ip;
      for (DWORD i = 0; i < pIpNetTable->dwNumEntries; ++i) {
        dwCurrIndex = pIpNetTable->table[i].dwIndex;

        macaddr(pIpNetTable->table[i].bPhysAddr,
                pIpNetTable->table[i].dwPhysAddrLen,
                szPrintablePhysAddr);

        inadTmp.s_addr = pIpNetTable->table[i].dwAddr;

        if(!strcmp(gateway, inet_ntoa(inadTmp))) {
          printf("id: %s\n", szPrintablePhysAddr);
          free(pIpNetTable);
          return 0; /* success */
        }
#if 0
        printf("  %-16s      %-17s\n",
               inet_ntoa(inadTmp), szPrintablePhysAddr);
#endif
      }
      free(pIpNetTable);
    }
  }
  else {
    printf("general error\n");
  }
  return 1; /* failure */
}

static int defaultgw(char *gateway) /* at least 128 bytes buffer */
{
  /* variables used for GetIfForwardTable */
  PMIB_IPFORWARDTABLE pIpForwardTable = NULL;
  DWORD dwSize = 0;
  DWORD dwRetVal = 0;

  char szDestIp[128];
  char szMaskIp[128];
  struct in_addr IpAddr;
  int i;

  if (GetIpForwardTable(NULL, &dwSize, 0) ==
      ERROR_INSUFFICIENT_BUFFER) {
    pIpForwardTable = (MIB_IPFORWARDTABLE *)malloc(dwSize);
    if (!pIpForwardTable) {
      printf("Error allocating memory\n");
      return 1;
    }
  }

  /* Note that the IPv4 addresses returned in GetIpForwardTable entries are in
   * network byte order
   */
  if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0)) == NO_ERROR) {
#if 0
    printf("Number of entries: %d\n",
           (int) pIpForwardTable->dwNumEntries);
#endif
    for (i = 0; i < (int) pIpForwardTable->dwNumEntries; i++) {
      /* Convert IPv4 addresses to strings */
      IpAddr.S_un.S_addr =
        (u_long) pIpForwardTable->table[i].dwForwardDest;
      strcpy_s(szDestIp, sizeof (szDestIp), inet_ntoa(IpAddr));
      IpAddr.S_un.S_addr =
        (u_long) pIpForwardTable->table[i].dwForwardMask;
      strcpy_s(szMaskIp, sizeof (szMaskIp), inet_ntoa(IpAddr));
      IpAddr.S_un.S_addr =
        (u_long) pIpForwardTable->table[i].dwForwardNextHop;
      strcpy_s(gateway, 128, inet_ntoa(IpAddr));

#if 0
      printf("\nRoute[%d] Dest IP: %s\n", i, szDestIp);
      printf("Route[%d] Subnet Mask: %s\n", i, szMaskIp);
      printf("Route[%d] Next Hop: %s\n", i, gateway);
      printf("Route[%d] If Index: %ld\n", i,
             pIpForwardTable->table[i].dwForwardIfIndex);

      printf("Route[%d] Age: %ld\n", i,
             pIpForwardTable->table[i].dwForwardAge);
      printf("Route[%d] Metric1: %ld\n", i,
             pIpForwardTable->table[i].dwForwardMetric1);
#else
      if(!strcmp("0.0.0.0", szDestIp)) {
        /* Default gatyway! */
        //printf("Default gateway: %s\n", gateway);
        break;
      }
#endif
    } /* for loop */
    free(pIpForwardTable);
  }
  else {
    printf("GetIpForwardTable failed.\n");
    free(pIpForwardTable);
    return 1;
  }

  return 0;
}

static int getprefix(void)
{
  ULONG size = 0;

  /* first ask for buffer size */
  ULONG rc = GetAdaptersAddresses(AF_INET6,
                                  GAA_FLAG_SKIP_MULTICAST|
                                  GAA_FLAG_SKIP_FRIENDLY_NAME,
                                  NULL, NULL, &size);

  if(ERROR_BUFFER_OVERFLOW == rc) {
    IP_ADAPTER_ADDRESSES *adpt = malloc(size);
    IP_ADAPTER_ADDRESSES *buffer = adpt;
    if(adpt) {
      /* now ask for the addresses for real */
      rc = GetAdaptersAddresses(AF_INET6,
                                GAA_FLAG_SKIP_MULTICAST|
                                GAA_FLAG_INCLUDE_PREFIX|
                                GAA_FLAG_SKIP_DNS_SERVER|
                                GAA_FLAG_SKIP_FRIENDLY_NAME,
                                NULL, adpt, &size);
      while(adpt) {
        if(adpt->OperStatus == IfOperStatusUp) {
          char buffer[100];
          printf("Name: %s\n", (char *)adpt->AdapterName);
#if 0
          printf("Flags: %x\n", adpt->Flags);
          printf("OperStatus: %x\n", adpt->OperStatus);
          printf("Global zone index: %d\n", adpt->ZoneIndices[ScopeLevelGlobal]);
#endif
          IP_ADAPTER_UNICAST_ADDRESS *ipadr = adpt->FirstUnicastAddress;
          while(ipadr) {
            LPSOCKADDR addr = ipadr->Address.lpSockaddr;
            struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *)addr;
            int i;
            printf("Address: %s\n",
                   inet_ntop(AF_INET6, &(sa_in6->sin6_addr),
                             buffer, sizeof(buffer)));
            printf("Prefix: %d bits\n", ipadr->OnLinkPrefixLength);
            ipadr = ipadr->Next;
          }
#if 0
          IP_ADAPTER_PREFIX *prefix = adpt->FirstPrefix;
          while(prefix) {
            struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *)&prefix->Address;
            int i;
            char buffer[100];
            printf("Address: (%d bits) %s\n", prefix->PrefixLength,
                   inet_ntop(AF_INET6, &(sa_in6->sin6_addr),
                             buffer, sizeof(buffer)));
            prefix = prefix->Next;
          }
#endif
        }
        adpt = adpt->Next;
      }
      free(buffer);
    }
    else
      return 2;
  }
  else
    return 1;
  return 0;
}

int main(void)
{
  char gateway[128];
  if(!defaultgw(gateway))
    arplist(gateway);

  getprefix();

  return 0;
}
