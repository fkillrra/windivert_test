#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <windows.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF 0xFFFF

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

int main(int argc, char *argv[])
{
	HANDLE handle;
	INT16 priority = 0;
	PVOID pPacket[MAXBUF];
	WINDIVERT_ADDRESS addr;
	UINT len;
	
	handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("error : WinDivertOpen()\n");
		return 0;
	}

	while (true)
	{
		first:
		if (!WinDivertRecv(handle, pPacket, sizeof(pPacket), &addr, &len))
		{
			printf("error : WinDivertRecv()\n");
		}

		PTCPPACKET tcp = (TCPPACKET *)pPacket;

		if (ntohs(tcp->tcp.SrcPort) == 80 || ntohs(tcp->tcp.DstPort) == 80)
		{
			printf("   >>> [Drop the packet] <<<<\n");
			printf("   >> Block DstPort : %d\n", ntohs(tcp->tcp.DstPort));
			printf("   >> Block SrcPort : %d\n", ntohs(tcp->tcp.SrcPort));
			printf("\n");
			goto first;
		}

		else goto send;

		send:
		if (!WinDivertSend(handle, pPacket, len, &addr, &len))
		{
			printf("error : WinDviertSend()\n");
			//continue;
		}
		goto first;
	}

	return 0;
}