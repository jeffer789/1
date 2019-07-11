#include <stdio.h>
#include <WinSock2.h>
#include <stdlib.h>
#include <memory.h>
#include <iostream>
#include <string.h>
#include "hacker.h"


#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP  "118.126.117.125"
#define PORT 8000

#define  CONNECT_FAIL "connect server failed"
#define  ATTACK_SUCCESS "攻击成功"
#define  ATTACK_FAIL "攻击失败"
#define  ATTACK_RECORD_SUCCESS "["

using namespace std;

int send_cmd(char *cmd, char *response) {
	int ret;

	strcat(cmd, " check:13243879166");

	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	wVersionRequested = MAKEWORD(1, 1);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		return -1;
	}
	if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1)
	{
		WSACleanup();
		return -1;
	}

	SOCKET sockClient = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(PORT);
	
	ret = connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	if (ret < 0) {
		strcpy(response, "connect server failed.");
		return -1;
	}

	//printf("sending.....\n");
	ret = send(sockClient, cmd, strlen(cmd) + 1, 0);
	if (ret <= 0) {
		printf(response, "send cmd failed.");
		return -1;
	}
	//printf("send ended. waiting for server\n");

	//printf("receiving.....\n");
	ret  = recv(sockClient, response, MAXSIZE, 0);
	if (ret <= 0) {
		printf(response, "receive response failed.");
		return -1;
	}
	
	closesocket(sockClient);
	WSACleanup();

	return 0;
}

int hk_404(char *id, char *response) {
	char buff[128];
	sprintf(buff, "cmd:attack_404 para:null id:%s", id);	
	return send_cmd(buff, response);
}

int hk_restore(char *id, char *response) {
	char buff[128];
	sprintf(buff, "cmd:attack_restore para:null id:%s", id);
	return send_cmd(buff, response);
}


int hk_tamper(char *id, char *para, char *response) {
	char buff[128];
	sprintf(buff, "cmd:attack_tamper para:%s id:%s", para, id);
	return send_cmd(buff, response);
}

int hk_record(char *id, char *response) {
	char buff[128];
	sprintf(buff, "cmd:attack_record para:null id:%s", id);
	return send_cmd(buff, response);
}


std::string UTF8ToGBK(const char* strUTF8)  
{  
	int len = MultiByteToWideChar(CP_UTF8, 0, strUTF8, -1, NULL, 0);  
	wchar_t* wszGBK = new wchar_t[len+1];  
	memset(wszGBK, 0, len*2+2);  
	MultiByteToWideChar(CP_UTF8, 0, strUTF8, -1, wszGBK, len);  
	len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);  
	char* szGBK = new char[len+1];  
	memset(szGBK, 0, len+1);  
	WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, szGBK, len, NULL, NULL);  
	std::string strTemp(szGBK);  
	if(wszGBK) delete[] wszGBK;  
	if(szGBK) delete[] szGBK;  
	return strTemp;  
}  

void GBKToUTF8(string &strGBK)
{
    int len=MultiByteToWideChar(CP_ACP, 0, strGBK.c_str(), -1, NULL,0);
    wchar_t * wszUtf8 = new wchar_t [len];
    memset(wszUtf8, 0, len);
    MultiByteToWideChar(CP_ACP, 0,  strGBK.c_str(), -1, wszUtf8, len);
 
    len = WideCharToMultiByte(CP_UTF8, 0, wszUtf8, -1, NULL, 0, NULL, NULL);
    char *szUtf8=new char[len + 1];
    memset(szUtf8, 0, len + 1);
    WideCharToMultiByte (CP_UTF8, 0, wszUtf8, -1, szUtf8, len, NULL,NULL);
 
    strGBK = szUtf8;
    delete[] szUtf8;
    delete[] wszUtf8;
}

bool check_response(const char *response) {
	if (!strncmp(response, ATTACK_SUCCESS, strlen(ATTACK_SUCCESS)) || 
		!strncmp(response, ATTACK_RECORD_SUCCESS, strlen(ATTACK_RECORD_SUCCESS))){
		return true;	
	} 

	return false;
}

