#include <winsock2.h>
#include <string.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <process.h>

#pragma comment(lib,"Ws2_32.lib")
#pragma warning(disable : 4996)

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

//func
LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam);
void CreateSockRaw();
void RetriveHost();
int Start();
void StartSniffing(void *param);
void ProcessPacket(char* Buffer, int Size);
void PrintSourceIp();
void PrintTcpPacket(char* Buffer, int Size);
void PrintPacketToEdit(void *param);
void PrintData(char* data, int Size);
void PrintIpHeader(char* Buffer);
void PrintIcmpPacket(char* Buffer, int Size);
void PrintUdpPacket(char *Buffer, int Size);


//======ipv4 structure===============================================
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;
//====================================================================

HINSTANCE g_hinst;
HWND hList;
HWND hEdit;

struct sockaddr_in source, dest;
struct in_addr addr;
int in = 0, i, j;
unsigned int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
unsigned long count_list = 0, select_list = 0;
bool flag;
SOCKET sniffer;
FILE *datafile;

char hostname[100];
struct hostent *local;
WSADATA wsa;

IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;

int WINAPI WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow)
{
	WNDCLASSEX wc; 
	HWND hwnd; 
	MSG msg; 


	memset(&wc, 0, sizeof(wc));
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);


	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszClassName = "WindowClass";
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION); 
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION); 

	if (!RegisterClassEx(&wc)) {
		MessageBox(NULL, "Window Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	g_hinst = hInstance;

	hwnd = CreateWindowEx(
		0,
		"WindowClass", 
		"Sniffer", 
		WS_VISIBLE | WS_OVERLAPPEDWINDOW, 
		CW_USEDEFAULT, 
		CW_USEDEFAULT, 
		640, 
		480, 
		HWND_DESKTOP,
		NULL, 
		hInstance, 
		NULL 
	);

	if (hwnd == NULL) {
		MessageBox(NULL, "Window Creation Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	ShowWindow(hwnd, nCmdShow);

	datafile = fopen("data_sniff.txt", "w+");
	if (datafile == NULL) {
		MessageBox(NULL, "Datafile Creation Failed", "Error", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	while (GetMessage(&msg, NULL, 0, 0) > 0) { /* If no error is received... */
		TranslateMessage(&msg); /* Translate key codes to chars if present */
		DispatchMessage(&msg); /* Send it to WndProc */
	}
	return msg.wParam;
}


LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	switch (Message) {

	case WM_DESTROY: {
		int ans;
		ans = MessageBox(hwnd, "패킷로그를 저장하시겠습니까?", "잠시만요!", MB_YESNOCANCEL | MB_ICONQUESTION);
		switch (ans) {
			case IDYES: {
				FILE *nFile, *oFile;
				oFile = fopen("data_sniff.txt", "r");
				char temp[256];
				OPENFILENAME OFN;
				char str[300];
				char lpstrFile[MAX_PATH] = "";
				memset(&OFN, 0, sizeof(OPENFILENAME));
				OFN.lStructSize = sizeof(OPENFILENAME);
				OFN.hwndOwner = hwnd;
				OFN.lpstrFilter = "Every File(*.*)\0*.*\0Text File\0*.txt;*.doc\0";
				OFN.lpstrFile = lpstrFile;
				OFN.nMaxFile = 256;
				OFN.lpstrInitialDir = "c:\\";
				if (GetSaveFileName(&OFN) != 0) {
					nFile = fopen(OFN.lpstrFile, "w+");
					
					while (fgets(temp, 15, oFile) != NULL) {
						fprintf(nFile, "%s", temp);
					}
					fclose(nFile);
				}
				
				fclose(oFile);
			}
			case IDNO: {
				fclose(datafile);
				closesocket(sniffer);
				WSACleanup();
				PostQuitMessage(0);
			break;
			}
			case IDCANCEL: { // 수정 요함
				fclose(datafile);
				closesocket(sniffer);
				WSACleanup();
				PostQuitMessage(0);
			break;
			}
		}
		break;
	}
	case WM_CREATE: {
		CreateWindow("button",
			"Start",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			500, 20, 100, 40,
			hwnd, (HMENU)1, g_hinst, NULL);
		CreateWindow("button",
			"Pause/Restart",
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			500, 100, 100, 40,
			hwnd, (HMENU)4, g_hinst, NULL);
		hList = CreateWindow("listbox",
			NULL,
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_NOTIFY | WS_BORDER,
			20, 20, 455, 300,
			hwnd, (HMENU)2, g_hinst, NULL);
		hEdit = CreateWindow("edit",
			NULL,
			WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY|
			ES_AUTOHSCROLL| ES_AUTOVSCROLL | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL,
			20, 320, 580, 100,
			hwnd, (HMENU)3, g_hinst, NULL);
		CreateSockRaw();
		RetriveHost();
		break;
	}
	case WM_COMMAND: {
		switch (LOWORD(wParam)) {
		case 1: { //button
			switch (HIWORD(wParam)) {
			case BN_CLICKED:
				flag = 1;
				if ((in = SendMessage(hList, LB_GETCURSEL, 0, 0)) >= 0) {
					Start();
				}
				else {
					MessageBox(hwnd, "인터페이스를 선택하세요!", "잠시만요!", MB_OK | MB_ICONEXCLAMATION);
				}
				break;
			}
			break;
		}
		case 2: { //listbox
			switch (HIWORD(wParam)) {
			case LBN_DBLCLK: {
				select_list = SendMessage(hList, LB_GETCURSEL, 0, 0);
				_beginthread(PrintPacketToEdit, 0, NULL);
				break;
			}
			}
			break;
		}
		case 4: {
			switch (HIWORD(wParam)) {
			case BN_CLICKED:
				if (flag == 1) {
					flag = 0;
				}
				else if(flag == 0){
					flag = 1;
					_beginthread(StartSniffing, 0, (void *)sniffer);
				}
				break;
			}
			break;
		}
		}
		break;
	}
	default:
		return DefWindowProc(hwnd, Message, wParam, lParam);
	}
	return 0;
}

void CreateSockRaw() {
	int idx = GetWindowTextLength(hEdit);

	SendMessage(hEdit, EM_SETSEL, idx, idx);
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"Initialising...\r\n");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"WSAStartup failed\r\n");		
	}
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"Initialised\r\n");

	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"Creating Raw Sock\r\n");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET) {
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"Failed to create raw socket\r\n");
	}
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"Created Socket\r\n");
}

void RetriveHost() {
	
	i = 0;

	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nError : ");
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)WSAGetLastError());
	}
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nHost Name : ");
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)hostname);

	local = gethostbyname(hostname);
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nAvailable Network Interface");
	if (local == NULL)
	{
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nError : ");
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)WSAGetLastError());
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)inet_ntoa(addr));
	}

	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nChose you want");
}

int Start() {
	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nBinding socket to local system and port 0 ...");
	if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
	{
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nbind failed : ");
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)inet_ntoa(addr));
		return 1;
	}
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nBinding successful");

	j = 1;
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR)
	{
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nWSAIoctl() failed.");
		return 1;
	}
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nSocket Set.");
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nStarted Sniffing.");
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nPacket Capture Statistics...");
	_beginthread(StartSniffing, 0, (void *)sniffer);
}

void StartSniffing(void *param) {
	SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nThread in");
	SOCKET sniff = (SOCKET)param;
	char *Buffer = (char *)malloc(65536);
	int mangobyte;

	if (Buffer == NULL)
	{
		SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"malloc() failed");
		return;
	}

	do
	{
		mangobyte = recvfrom(sniff, Buffer, 65536, 0, 0, 0); 

		if (mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\nrecvfrom() failed");
		}
	} while (mangobyte > 0 && flag == 1);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size) {
	iphdr = (IPV4_HDR *)Buffer;
	++total;
	TCHAR lpOut[1024];

	switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
	{
	case 1: //ICMP Protocol
		++icmp;
		PrintIcmpPacket(Buffer, Size);
		PrintSourceIp();
		break;

	case 2: //IGMP Protocol
		++igmp;
		break;

	case 6: //TCP Protocol
		++tcp;		
		PrintTcpPacket(Buffer, Size);
		PrintSourceIp();
		break;

	case 17: //UDP Protocol
		++udp;
		PrintUdpPacket(Buffer, Size);
		PrintSourceIp();
		break;

	default: //Some Other Protocol like ARP etc.
		++others;
		break;
	}
}

void PrintSourceIp() {
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;
	SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)inet_ntoa(source.sin_addr));
	count_list++;
}

void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen);

	fprintf(datafile, "\n!@#%d_",count_list);
	fprintf(datafile, "\n***********************TCP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(datafile, "\n");
	fprintf(datafile, "TCP Header\n");
	fprintf(datafile, " |-Source Port : %u\n", ntohs(tcpheader->source_port));
	fprintf(datafile, " |-Destination Port : %u\n", ntohs(tcpheader->dest_port));
	fprintf(datafile, " |-Sequence Number : %u\n", ntohl(tcpheader->sequence));
	fprintf(datafile, " |-Acknowledge Number : %u\n", ntohl(tcpheader->acknowledge));
	fprintf(datafile, " |-Header Length : %d DWORDS or %d BYTES\n"
		, (unsigned int)tcpheader->data_offset, (unsigned int)tcpheader->data_offset * 4);
	fprintf(datafile, " |-CWR Flag : %d\n", (unsigned int)tcpheader->cwr);
	fprintf(datafile, " |-ECN Flag : %d\n", (unsigned int)tcpheader->ecn);
	fprintf(datafile, " |-Urgent Flag : %d\n", (unsigned int)tcpheader->urg);
	fprintf(datafile, " |-Acknowledgement Flag : %d\n", (unsigned int)tcpheader->ack);
	fprintf(datafile, " |-Push Flag : %d\n", (unsigned int)tcpheader->psh);
	fprintf(datafile, " |-Reset Flag : %d\n", (unsigned int)tcpheader->rst);
	fprintf(datafile, " |-Synchronise Flag : %d\n", (unsigned int)tcpheader->syn);
	fprintf(datafile, " |-Finish Flag : %d\n", (unsigned int)tcpheader->fin);
	fprintf(datafile, " |-Window : %d\n", ntohs(tcpheader->window));
	fprintf(datafile, " |-Checksum : %d\n", ntohs(tcpheader->checksum));
	fprintf(datafile, " |-Urgent Pointer : %d\n", tcpheader->urgent_pointer);
	fprintf(datafile, "\n");
	fprintf(datafile, " DATA Dump ");
	fprintf(datafile, "\n");

	fprintf(datafile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(datafile, "TCP Header\n");
	PrintData(Buffer + iphdrlen, tcpheader->data_offset * 4);

	fprintf(datafile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + tcpheader->data_offset * 4
		, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));

	fprintf(datafile, "\n###########################################################");

	fprintf(datafile, "\n#@!%d_", count_list);	
}

void PrintUdpPacket(char *Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	udpheader = (UDP_HDR *)(Buffer + iphdrlen);

	fprintf(datafile, "\n!@#%d_", count_list);
	fprintf(datafile, "\n\n***********************UDP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(datafile, "\nUDP Header\n");
	fprintf(datafile, " |-Source Port : %d\n", ntohs(udpheader->source_port));
	fprintf(datafile, " |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	fprintf(datafile, " |-UDP Length : %d\n", ntohs(udpheader->udp_length));
	fprintf(datafile, " |-UDP Checksum : %d\n", ntohs(udpheader->udp_checksum));

	fprintf(datafile, "\n");
	fprintf(datafile, "IP Header\n");

	PrintData(Buffer, iphdrlen);

	fprintf(datafile, "UDP Header\n");

	PrintData(Buffer + iphdrlen, sizeof(UDP_HDR));

	fprintf(datafile, "Data Payload\n");

	PrintData(Buffer + iphdrlen + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - iphdr->ip_header_len * 4));

	fprintf(datafile, "\n###########################################################");
	fprintf(datafile, "\n#@!%d_", count_list);
}

void PrintIcmpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	icmpheader = (ICMP_HDR*)(Buffer + iphdrlen);

	fprintf(datafile, "\n!@#%d_", count_list);
	fprintf(datafile, "\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer);

	fprintf(datafile, "\n");

	fprintf(datafile, "ICMP Header\n");
	fprintf(datafile, " |-Type : %d", (unsigned int)(icmpheader->type));

	if ((unsigned int)(icmpheader->type) == 11)
	{
		fprintf(datafile, " (TTL Expired)\n");
	}
	else if ((unsigned int)(icmpheader->type) == 0)
	{
		fprintf(datafile, " (ICMP Echo Reply)\n");
	}

	fprintf(datafile, " |-Code : %d\n", (unsigned int)(icmpheader->code));
	fprintf(datafile, " |-Checksum : %d\n", ntohs(icmpheader->checksum));
	fprintf(datafile, " |-ID : %d\n", ntohs(icmpheader->id));
	fprintf(datafile, " |-Sequence : %d\n", ntohs(icmpheader->seq));
	fprintf(datafile, "\n");

	fprintf(datafile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(datafile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof(ICMP_HDR));

	fprintf(datafile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + sizeof(ICMP_HDR), (Size - sizeof(ICMP_HDR) - iphdr->ip_header_len * 4));

	fprintf(datafile, "\n###########################################################");
	fprintf(datafile, "\n#@!%d_", count_list);
}

void PrintIpHeader(char* Buffer)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(datafile, "\n");
	fprintf(datafile, "IP Header\n");
	fprintf(datafile, " |-IP Version : %d\n", (unsigned int)iphdr->ip_version);
	fprintf(datafile, " |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->ip_header_len, ((unsigned int)(iphdr->ip_header_len)) * 4);
	fprintf(datafile, " |-Type Of Service : %d\n", (unsigned int)iphdr->ip_tos);
	fprintf(datafile, " |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->ip_total_length));
	fprintf(datafile, " |-Identification : %d\n", ntohs(iphdr->ip_id));
	fprintf(datafile, " |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	fprintf(datafile, " |-Dont Fragment Field : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	fprintf(datafile, " |-More Fragment Field : %d\n", (unsigned int)iphdr->ip_more_fragment);
	fprintf(datafile, " |-TTL : %d\n", (unsigned int)iphdr->ip_ttl);
	fprintf(datafile, " |-Protocol : %d\n", (unsigned int)iphdr->ip_protocol);
	fprintf(datafile, " |-Checksum : %d\n", ntohs(iphdr->ip_checksum));
	fprintf(datafile, " |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(datafile, " |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

void PrintData(char* data, int Size)
{
	char a, line[17], c;
	int j;

	//loop over each character and print
	for (i = 0; i < Size; i++)
	{
		c = data[i];

		//Print the hex value for every character , with a space. Important to make unsigned
		fprintf(datafile, " %.2x", (unsigned char)c);

		//Add the character to data line. Important to make unsigned
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

		line[i % 16] = a;

		//if last character of a line , then print the line - 16 characters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			fprintf(datafile, "          ");

			//Print additional spaces for last lines which might be less than 16 characters in length
			for (j = strlen(line); j < 16; j++)
			{
				fprintf(datafile, "   ");
			}

			fprintf(datafile, "%s \n", line);
		}
	}

	fprintf(datafile, "\n");
}

void PrintPacketToEdit(void *param) {
	int number = select_list -1;
	FILE *find;
	char temp[256], *check_first, *check_second, *check_newline;
	TCHAR lpOut[1024], lpOut2[1024];
	int flag_find = 0;
	int len;
	len = GetWindowTextLength(hEdit);

	find = fopen("data_sniff.txt", "r");

	wsprintf(lpOut, TEXT("!@#%d_"), number);
	wsprintf(lpOut2, TEXT("#@!%d_"), number);

	while (fgets(temp, 15, find) != NULL) {
		check_first = strstr(temp, lpOut);
		check_second = strstr(temp, lpOut2);
		check_newline = strstr(temp, "\n");
		if (check_first != NULL) {
			flag_find = 1;
		}
		if (check_second != NULL) {
			flag_find = 0;
			break;
		}
		if (check_newline != NULL) {
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)"\r\n.");
		}
		if (flag_find == 1) {
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)temp);
		}
	}
	fclose(find);
}
