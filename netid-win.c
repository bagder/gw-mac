#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <iphlpapi.h>
#include <iptypes.h>

static BOOL macaddr(BYTE addr[], DWORD len, char str[])
{
  DWORD i;
  str[0] = '\0';
  if (addr == NULL || !len)
    return FALSE;

  for (i = 0; i < len; i++)
    sprintf_s(str+(i*3), sizeof(str+(i*3)),
              "%02x%s", ((int)addr[i])&0xff,
              (i == len-1)?"":":" );

  return TRUE;
}

void arplist(void)
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
      char szType[128];
      char szIpAddr[128];
      struct in_addr inadTmp;
      DWORD dwCurrIndex;
      for (DWORD i = 0; i < pIpNetTable->dwNumEntries; ++i) {
        dwCurrIndex = pIpNetTable->table[i].dwIndex;

        macaddr(pIpNetTable->table[i].bPhysAddr,
                pIpNetTable->table[i].dwPhysAddrLen,
                szPrintablePhysAddr);

        inadTmp.s_addr = pIpNetTable->table[i].dwAddr;

        switch (pIpNetTable->table[i].dwType) {
        case 1:
          strcpy_s(szType, sizeof(szType), "Other");
          break;

        case 2:
          strcpy_s(szType,sizeof(szType), "Invalidated");
          break;

        case 3:
          strcpy_s(szType,sizeof(szType), "Dynamic");
          break;

        case 4:
          strcpy_s(szType,sizeof(szType), "Static");
          break;

        default:
          strcpy_s(szType, sizeof(szType), "InvalidType");
        }

        printf("  %-16s      %-17s     %-11s\n",
               inet_ntoa(inadTmp), szPrintablePhysAddr, szType);
      }

      free(pIpNetTable);
    }
  }
  else {
    printf("general error\n");
  }
}

int main(void)
{
  arplist();
  return 0;
}
