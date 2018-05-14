/*
2018-05-14 f.killrra's first WinDivert_test
I fixed LABEL (goto) & Determined if the packet is TCP.
*/
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
		if (!WinDivertRecv(handle, pPacket, sizeof(pPacket), &addr, &len))
		{
			printf("error : WinDivertRecv()\n");
			continue;
		}

		PTCPPACKET tcp = (TCPPACKET *)pPacket;	
		
		if (tcp->ip.Protocol == 0x06)	//When the TCP packet
		{
			if (ntohs(tcp->tcp.SrcPort) == 80 || ntohs(tcp->tcp.DstPort) == 80)		//When the port number is 80, try to drop the packet
			{
				printf("   >>> [Drop the packet] <<<<\n");
				printf("   >> Block DstPort : %d\n", ntohs(tcp->tcp.DstPort));
				printf("   >> Block SrcPort : %d\n", ntohs(tcp->tcp.SrcPort));
				printf("\n");
				continue;
			}
			continue;
		}
		
		if (!WinDivertSend(handle, pPacket, len, &addr, &len))
		{
			printf("error : WinDviertSend()\n");
			continue;
		}
	}

	return 0;
}