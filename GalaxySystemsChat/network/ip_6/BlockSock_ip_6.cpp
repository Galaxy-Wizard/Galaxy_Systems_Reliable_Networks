// blocksock.cpp (CBlockingSocketException, CBlockingSocket, CHttpBlockingSocket)
#include "pch.h"

#include "blocksock_ip_6.h"

#include <list>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")

#pragma comment (lib, "Normaliz.lib")

#pragma comment (lib, "dnsapi.lib")

namespace network
{
	namespace ip_6
	{


		// Class CBlockingSocketException
			CBlockingSocketException_ip_6::CBlockingSocketException_ip_6(wchar_t* pchMessage)
		{
			m_strMessage = pchMessage;
			m_nError = WSAGetLastError();
		}

		BOOL CBlockingSocketException_ip_6::GetErrorMessage(LPWSTR lpstrError, UINT nMaxError,
			PUINT pnHelpContext /*= NULL*/)
		{

			wchar_t text[500];
			if (m_nError == 0) {
				wsprintf((LPWSTR)text, _T("%s: Error"), m_strMessage.GetBuffer());
			}
			else {
				wsprintf((LPWSTR)text, _T("%s: Error #%d"), m_strMessage.GetBuffer(), m_nError);
			}
			wcsncpy_s((wchar_t*)lpstrError, nMaxError - 1, text, nMaxError - 1);
			return TRUE;
		}

		// Class CBlockingSocket
		IMPLEMENT_DYNAMIC(CBlockingSocket_ip_6, CObject)

			void CBlockingSocket_ip_6::Cleanup()
		{
			// doesn't throw an exception because it's called in a catch block
			if (m_hSocket == NULL) return;
			VERIFY(closesocket(m_hSocket) != SOCKET_ERROR);
			m_hSocket = NULL;
		}

		void CBlockingSocket_ip_6::Create(int nType /* = SOCK_STREAM */, UINT nProtocol /* = 0 */)
		{
			ASSERT(m_hSocket == NULL);
			if ((m_hSocket = socket(AF_INET6, nType, nProtocol)) == INVALID_SOCKET) {
				throw new CBlockingSocketException_ip_6(L"Creating socket");
			}
		}

		void CBlockingSocket_ip_6::Bind(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			if (bind(m_hSocket, (sockaddr*)psa, sizeof(sockaddr_in6)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Binding socket");
			}
		}

		void CBlockingSocket_ip_6::Listen()
		{
			ASSERT(m_hSocket != NULL);
			if (listen(m_hSocket, 5) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Listening on socket");
			}
		}

		BOOL CBlockingSocket_ip_6::Accept(CBlockingSocket_ip_6& sConnect, LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			ASSERT(sConnect.m_hSocket == NULL);
			int nLengthAddr = sizeof(sockaddr_in6);
			sConnect.m_hSocket = accept(m_hSocket, (sockaddr*)psa, &nLengthAddr);
			if (sConnect == INVALID_SOCKET) {
				// no exception if the listen was canceled
				if (WSAGetLastError() != WSAEINTR) {
					throw new CBlockingSocketException_ip_6(L"Receiving on socket");
				}
				return FALSE;
			}
			return TRUE;
		}

		void CBlockingSocket_ip_6::Close()
		{
			if (NULL == m_hSocket)
				return;

			if (closesocket(m_hSocket) == SOCKET_ERROR) {
				// should be OK to close if closed already
				throw new CBlockingSocketException_ip_6(L"Closing socket");
			}
			m_hSocket = NULL;
		}

		void CBlockingSocket_ip_6::Connect(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			// should timeout by itself
			if (connect(m_hSocket, (sockaddr*)psa, sizeof(sockaddr_in6)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Connecting");
			}
		}

		int CBlockingSocket_ip_6::Write(const char* pch, const int nSize, const int nSecs)
		{
			int nBytesSent = 0;
			int nBytesThisTime;
			const char* pch1 = pch;
			do {
				nBytesThisTime = Send(pch1, nSize - nBytesSent, nSecs);
				nBytesSent += nBytesThisTime;
				pch1 += nBytesThisTime;
			} while (nBytesSent < nSize);
			return nBytesSent;
		}

		int CBlockingSocket_ip_6::Send(const char* pch, const int nSize, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			// returned value will be less than nSize if client cancels the reading
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, NULL, &fd, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_6(L"Sending time out");
			}
			int nBytesSent;
			if ((nBytesSent = send(m_hSocket, pch, nSize, 0)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Sending");
			}
			return nBytesSent;
		}

		int CBlockingSocket_ip_6::Receive(char* pch, const int nSize, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, &fd, NULL, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_6(L"Receiving time out");
			}

			int nBytesReceived;
			if ((nBytesReceived = recv(m_hSocket, pch, nSize, 0)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Receiving");
			}
			return nBytesReceived;
		}

		int CBlockingSocket_ip_6::ReceiveDatagram(char* pch, const int nSize, LPSOCKADDR6 psa, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, &fd, NULL, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_6(L"Receiving time out");
			}

			// input buffer should be big enough for the entire datagram
			int nFromSize = sizeof(sockaddr_in6);
			int nBytesReceived = recvfrom(m_hSocket, pch, nSize, 0, (sockaddr*)psa, &nFromSize);
			if (nBytesReceived == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Receiving datagram");
			}
			return nBytesReceived;
		}

		int CBlockingSocket_ip_6::SendDatagram(const char* pch, const int nSize, LPSOCKADDR6 psa, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, NULL, &fd, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_6(L"Sending time out");
			}

			int nBytesSent = sendto(m_hSocket, pch, nSize, 0, (sockaddr*)psa, sizeof(sockaddr_in6));
			if (nBytesSent == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Sending datagram");
			}
			return nBytesSent;
		}

		void CBlockingSocket_ip_6::GetPeerAddr(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			// gets the address of the socket at the other end
			int nLengthAddr = sizeof(sockaddr_in6);
			if (getpeername(m_hSocket, (sockaddr*)psa, &nLengthAddr) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Getting remote name");
			}
		}

		void CBlockingSocket_ip_6::GetSockAddr(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			// gets the address of the socket at this end
			int nLengthAddr = sizeof(sockaddr_in6);
			if (getsockname(m_hSocket, (sockaddr*)psa, &nLengthAddr) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Getting name of socket");
			}
		}

		//static
		CSockAddr_ip_6 CBlockingSocket_ip_6::GetHostByName(const char* pchName, const USHORT ushPort /* = 0 */)
		{
			char local_port[10];
			_itoa_s(ushPort, local_port, 10 - 1, 10);

			struct addrinfo* result = NULL;
			auto ipv6_addresses = GetAddressInformationIPv6(pchName, &result);
			if (ipv6_addresses.size() == 0) {
				throw new CBlockingSocketException_ip_6(L"Getting address by name");
			}
			SOCKADDR_IN6 pulAddr = (SOCKADDR_IN6)ipv6_addresses.front();

			if (result == NULL)
			{
				throw new CBlockingSocketException_ip_6(L"Getting address by name");
			}
			SOCKADDR_IN6 sockTemp;
			memcpy(&sockTemp, result->ai_addr, sizeof(SOCKADDR_IN6)); // address is already in network byte order
			freeaddrinfo(result);
			return sockTemp;
		}

		//static
		const char* CBlockingSocket_ip_6::GetHostByAddr(LPSOCKADDR6 psa)
		{
			auto name = GetNameInformationIPv6(((LPSOCKADDR_IN6)psa)->sin6_addr);
			return name;
		}

		// Class CHttpBlockingSocket
		IMPLEMENT_DYNAMIC(CHttpBlockingSocket_ip_6, CBlockingSocket_ip_6)

			CHttpBlockingSocket_ip_6::CHttpBlockingSocket_ip_6()
		{
			m_pReadBuf = new char[nSizeRecv];
			m_nReadBuf = 0;
		}

		CHttpBlockingSocket_ip_6::~CHttpBlockingSocket_ip_6()
		{
			delete[] m_pReadBuf;
		}

		int CHttpBlockingSocket_ip_6::ReadHttpHeaderLine(char* pch, const int nSize, const int nSecs)
			// reads an entire header line through CRLF (or socket close)
			// inserts zero string terminator, object maintains a buffer
		{
			int nBytesThisTime = m_nReadBuf;
			int nLineLength = 0;
			char* pch1 = m_pReadBuf;
			char* pch2;
			do {
				// look for lf (assume preceded by cr)
				if ((pch2 = (char*)memchr(pch1, '\n', nBytesThisTime)) != NULL) {
					ASSERT((pch2) > m_pReadBuf);
					ASSERT(*(pch2 - 1) == '\r');
					nLineLength = int(pch2 - m_pReadBuf) + 1;
					if (nLineLength >= nSize) nLineLength = nSize - 1;
					memcpy(pch, m_pReadBuf, nLineLength); // copy the line to caller
					m_nReadBuf -= nLineLength;
					memmove(m_pReadBuf, pch2 + 1, m_nReadBuf); // shift remaining characters left
					break;
				}
				pch1 += nBytesThisTime;
				nBytesThisTime = Receive(m_pReadBuf + m_nReadBuf, nSizeRecv - m_nReadBuf, nSecs);
				if (nBytesThisTime <= 0) { // sender closed socket or line longer than buffer
					throw new CBlockingSocketException_ip_6(L"Reading header");
				}
				m_nReadBuf += nBytesThisTime;
			} while (TRUE);
			*(pch + nLineLength) = '\0';
			return nLineLength;
		}

		int CHttpBlockingSocket_ip_6::ReadHttpResponse(char* pch, const int nSize, const int nSecs)
			// reads remainder of a transmission through buffer full or socket close
			// (assume headers have been read already)
		{
			int nBytesToRead, nBytesThisTime, nBytesRead = 0;
			if (m_nReadBuf > 0) { // copy anything already in the recv buffer
				memcpy(pch, m_pReadBuf, m_nReadBuf);
				pch += m_nReadBuf;
				nBytesRead = m_nReadBuf;
				m_nReadBuf = 0;
			}
			do { // now pass the rest of the data directly to the caller
				nBytesToRead = min(nSizeRecv, nSize - nBytesRead);
				nBytesThisTime = Receive(pch, nBytesToRead, nSecs);
				if (nBytesThisTime <= 0) break; // sender closed the socket
				pch += nBytesThisTime;
				nBytesRead += nBytesThisTime;
			} while (nBytesRead <= nSize);
			return nBytesRead;
		}

		void LogBlockingSocketException(LPVOID pParam, wchar_t* pch, CBlockingSocketException_ip_6* pe)
		{	// pParam holds the HWND for the destination window (in another thread)
			CString strGmt = CTime::GetCurrentTime().FormatGmt("%m/%d/%y %H:%M:%S GMT");
			wchar_t text1[500], text2[1500];
			pe->GetErrorMessage((LPWSTR)text2, 1500);
			wsprintf((wchar_t*)text1, L"Networking error --%s %s -- %s\r\n", pch, text2, strGmt.GetBuffer());
			::SendMessage((HWND)pParam, EM_SETSEL, (WPARAM)65534, 65535);
			::SendMessage((HWND)pParam, EM_REPLACESEL, (WPARAM)0, (LPARAM)text1);
		}

		bool domain_name_to_internet_6_name(CStringW domain_name, CStringA& internet_name)
		{
			std::list<CStringA> local_internet_name;

			const size_t CONST_MESSAGE_LENGTH = 500;

			wchar_t local_domain_name_unicode[CONST_MESSAGE_LENGTH];

			ZeroMemory(local_domain_name_unicode, sizeof(wchar_t) * CONST_MESSAGE_LENGTH);

			if (IdnToAscii(0, domain_name, domain_name.GetLength(), local_domain_name_unicode, CONST_MESSAGE_LENGTH) == 0)
			{
				const int local_error_message_size = 500;
				wchar_t local_error_message[local_error_message_size];

				const int local_system_error_message_size = local_error_message_size - 250;
				wchar_t local_system_error_message[local_system_error_message_size];

				wcscpy_s(local_system_error_message, local_system_error_message_size, L"IdnToAscii finished with error");

				CString local_time_string = CTime::GetCurrentTime().FormatGmt("%d/%m/%y %H:%M:%S GMT");

				wsprintf((wchar_t*)local_error_message, L"Networking error -- %s -- %s\r\n", local_system_error_message, local_time_string.GetBuffer());

				MessageBox(0, local_error_message, CString(L"Error"), MB_ICONERROR);

				return false;
			}

			//	DNS_STATUS
			//WINAPI
			//DnsQuery_W(
			//    IN      PCWSTR          pszName,
			//    IN      WORD            wType,
			//    IN      DWORD           Options,                         
			//    IN      PIP4_ARRAY      aipServers            OPTIONAL,
			//    IN OUT  PDNS_RECORD *   ppQueryResults        OPTIONAL,
			//    IN OUT  PVOID *         pReserved             OPTIONAL
			//    );


			PDNS_RECORD   ppQueryResults;

			ZeroMemory(&ppQueryResults, sizeof(ppQueryResults));

			if (DnsQuery_W(local_domain_name_unicode, DNS_TYPE_AAAA, 0, NULL, &ppQueryResults, NULL) == ERROR_SUCCESS)
			{
				for (PDNS_RECORD ptr = ppQueryResults; ptr != NULL; ptr = ptr->pNext)
				{
					if (ptr->wType == DNS_TYPE_AAAA)
					{
						if (ptr->wDataLength != 0)
						{
							char local_address_buffer[100];
							inet_ntop(AF_INET6, &ptr->Data.AAAA.Ip6Address.IP6Byte, local_address_buffer, 100);
							//internet_name = local_address_buffer;

							local_internet_name.push_back(local_address_buffer);

							//					return true;
							//					MessageBoxA(0,internet_name,CStringA("Information"),MB_ICONINFORMATION);
						}
					}
				}

				DnsFree(ppQueryResults, DnsFreeRecordList);

				if (local_internet_name.size() != 0)
				{
					internet_name = *local_internet_name.begin();
				}
				else
				{
					return false;
				}

				return true;
			}

			return false;
		}

		const int BUF_SIZE = 4092;

		int lookup_addr_indx_ip_6(int indx,
			sockaddr_in6* addr)
		{
#ifdef WIN32
			LPSOCKET_ADDRESS_LIST list = NULL;
			SOCKET  sc = 0;
			char  buf[BUF_SIZE];
			int len = 0;
			int ret = 0;

			sc = socket(AF_INET6, SOCK_RAW, IPPROTO_IP);
			if (sc == INVALID_SOCKET) {
				return (-1);
			}
			ret = WSAIoctl(sc,
				SIO_ADDRESS_LIST_QUERY,
				NULL,
				0,
				buf,
				BUF_SIZE,
				(unsigned long*)&len,
				NULL,
				NULL);
			closesocket(sc);
			if (ret != 0 || len <= 0) {
				return(-2);
			}
			list = (LPSOCKET_ADDRESS_LIST)buf;
			if (list->iAddressCount <= 0) {
				return (-3);
			}
			for (int i = 0; i <= indx && i < list->iAddressCount; ++i) {
				// found address
				if (i == indx) {
					memcpy(addr,
						list->Address[i].lpSockaddr, list->Address[i].iSockaddrLength);
					return (1);
				}
			}
			//	finished with addresses
			return (0);
#else
			struct ifconf ifc;
			struct ifreq* ifr = NULL;
			char buf[BUF_SIZE];
			int ret = 0;
			int off = 0;
			int cnt = 0;
			int cdx = 0;
			int sc = 0;
			sc = socket(AF_INET6, SOCK_DGRAM, 0);
			if (sc < 0) {
				return (-1);
			}
			ifc.ifc_len = BUF_SIZE;
			ifc.ifc_buf = buf;
			ret = ioctl(sc, SIOCGIFCONF, &ifc);
			if (ret < 0) {
				return (-2);
			}
			ifr = ifc.ifc_req;
			while (cnt < ifc.ifc_len && cdx <= indx) {
				if (ifr->ifr_addr.sa_family == AF_INET) {
					if (cdx == indx) {
						memcpy(addr, &ifr->ifr_addr.sa_data[2], 4);
						return (1);
					}
					++cdx;
				}
				off = IFNAMSIZ + ifr->ifr_addr.sa_len;
				cnt += off;
				((char*)ifr) += off;
			}
			close(sc);
#endif
			return (0);
		}


		std::list<SOCKADDR_IN6> GetAddressInformationIPv6(const char* pchName, struct addrinfo* *result)
		{
			std::list<SOCKADDR_IN6> Results;
			//SOCKADDR_IN6 Result;
			INT iRetval;

			DWORD dwRetval;

			int i = 1;

			//struct addrinfo* result = NULL;
			struct addrinfo* ptr = NULL;
			struct addrinfo hints;

			struct sockaddr_in* sockaddr_ipv4;
			//    struct sockaddr_in6 *sockaddr_ipv6;
			LPSOCKADDR sockaddr_ip;

			wchar_t ipstringbuffer[46];
			DWORD ipbufferlength = 46;

			//--------------------------------
			// Setup the hints address info structure
			// which is passed to the getaddrinfo() function
			ZeroMemory(&hints, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			//--------------------------------
			// Call getaddrinfo(). If the call succeeds,
			// the result variable will hold a linked list
			// of addrinfo structures containing response
			// information
			dwRetval = getaddrinfo(pchName, "0", &hints, result);
			if (dwRetval != 0) {
				CString local_error_message;
				local_error_message.Format(L"getaddrinfo failed with error: %d\n", dwRetval);
				throw local_error_message;
				return Results;
			}

			//printf("getaddrinfo returned success\n");
			// Retrieve each address and print out the hex bytes
			for (ptr = *result; ptr != NULL; ptr = ptr->ai_next) {

				//printf("getaddrinfo response %d\n", i++);
				//printf("\tFlags: 0x%x\n", ptr->ai_flags);
				//printf("\tFamily: ");
				switch (ptr->ai_family) {
				case AF_UNSPEC:
					//printf("Unspecified\n");
					break;
				case AF_INET:
					//printf("AF_INET (IPv4)\n");
					sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
					char local_buffer[100];
					inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, local_buffer, 100);
					//	IPv4 address 
					//Result.Format("%s", local_buffer);
					//Results.push_back(Result);
					break;
				case AF_INET6:
					printf("AF_INET6 (IPv6)\n");
					// the InetNtop function is available on Windows Vista and later
					// sockaddr_ipv6 = (struct sockaddr_in6 *) ptr->ai_addr;
					// printf("\tIPv6 address %s\n",
					//    InetNtop(AF_INET6, &sockaddr_ipv6->sin6_addr, ipstringbuffer, 46) );

					// We use WSAAddressToString since it is supported on Windows XP and later
					sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
					// The buffer length is changed by each call to WSAAddresstoString
					// So we need to set it for each iteration through the loop for safety
					ipbufferlength = 46;
					iRetval = WSAAddressToString(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
						ipstringbuffer, &ipbufferlength);
					if (iRetval)
					{
						CString local_error_message;
						local_error_message.Format(L"WSAAddressToString failed with %u\n", WSAGetLastError());
						throw local_error_message;
					}
					else
					{
						//	IPv6 address 
						//Result.Format("%s", (wchar_t*)ipstringbuffer);
						Results.push_back(*(LPSOCKADDR6)sockaddr_ip);
					}
					break;
				case AF_NETBIOS:
					//printf("AF_NETBIOS (NetBIOS)\n");
					break;
				default:
					//printf("Other %ld\n", ptr->ai_family);
					break;
				}
				//printf("\tSocket type: ");
				switch (ptr->ai_socktype) {
				case 0:
					//printf("Unspecified\n");
					break;
				case SOCK_STREAM:
					//printf("SOCK_STREAM (stream)\n");
					break;
				case SOCK_DGRAM:
					//printf("SOCK_DGRAM (datagram) \n");
					break;
				case SOCK_RAW:
					//printf("SOCK_RAW (raw) \n");
					break;
				case SOCK_RDM:
					//printf("SOCK_RDM (reliable message datagram)\n");
					break;
				case SOCK_SEQPACKET:
					//printf("SOCK_SEQPACKET (pseudo-stream packet)\n");
					break;
				default:
					//printf("Other %ld\n", ptr->ai_socktype);
					break;
				}
				//printf("\tProtocol: ");
				switch (ptr->ai_protocol) {
				case 0:
					//printf("Unspecified\n");
					break;
				case IPPROTO_TCP:
					//printf("IPPROTO_TCP (TCP)\n");
					break;
				case IPPROTO_UDP:
					//printf("IPPROTO_UDP (UDP) \n");
					break;
				default:
					//printf("Other %ld\n", ptr->ai_protocol);
					break;
				}
				//printf("\tLength of this sockaddr: %d\n", ptr->ai_addrlen);
				//printf("\tCanonical name: %s\n", ptr->ai_canonname);
			}

			//freeaddrinfo(*result);

			return Results;
		}

		CStringA GetNameInformationIPv6(IN6_ADDR parameter)
		{
			int iResult = 0;

			DWORD dwRetval;

			struct sockaddr_in6 saGNI;
			char hostname[NI_MAXHOST];
			char servInfo[NI_MAXSERV];
			u_short port = 27015;

			//-----------------------------------------
			// Set up sockaddr_in structure which is passed
			// to the getnameinfo function
			ZeroMemory(&saGNI, sizeof(sockaddr_in6));
			saGNI.sin6_family = AF_INET6;
			saGNI.sin6_addr = parameter;
			saGNI.sin6_port = htons(port);
			

			//-----------------------------------------
			// Call getnameinfo
			dwRetval = getnameinfo((struct sockaddr*)&saGNI,
				sizeof(struct sockaddr),
				hostname,
				NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);

			if (dwRetval != 0) {
				CString local_error;
				local_error.Format(L"getnameinfo failed with error # %ld\n", WSAGetLastError());
				throw local_error;
				return CStringA();
			}
			else {
				//printf("getnameinfo returned hostname = %s\n", hostname);
				return CStringA(hostname);
			}

			return CStringA();
		}
	}
}
