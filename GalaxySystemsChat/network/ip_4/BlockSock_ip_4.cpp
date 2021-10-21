// blocksock.cpp (CBlockingSocketException, CBlockingSocket, CHttpBlockingSocket)
#include "pch.h"

#include "blocksock_ip_4.h"

#include <list>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace network
{
	namespace ip_4
	{


		// Class CBlockingSocketException
			CBlockingSocketException_ip_4::CBlockingSocketException_ip_4(wchar_t* pchMessage)
		{
			m_strMessage = pchMessage;
			m_nError = WSAGetLastError();
		}

		BOOL CBlockingSocketException_ip_4::GetErrorMessage(LPWSTR lpstrError, UINT nMaxError,
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
		IMPLEMENT_DYNAMIC(CBlockingSocket_ip_4, CObject)

			void CBlockingSocket_ip_4::Cleanup()
		{
			// doesn't throw an exception because it's called in a catch block
			if (m_hSocket == NULL) return;
			VERIFY(closesocket(m_hSocket) != SOCKET_ERROR);
			m_hSocket = NULL;
		}

		void CBlockingSocket_ip_4::Create(int nType /* = SOCK_STREAM */, UINT nProtocol /* = 0 */)
		{
			ASSERT(m_hSocket == NULL);
			if ((m_hSocket = socket(AF_INET, nType, nProtocol)) == INVALID_SOCKET) {
				throw new CBlockingSocketException_ip_4(L"Creating socket");
			}
		}

		void CBlockingSocket_ip_4::Bind(LPCSOCKADDR psa)
		{
			ASSERT(m_hSocket != NULL);
			if (bind(m_hSocket, psa, sizeof(SOCKADDR)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Binding socket");
			}
		}

		void CBlockingSocket_ip_4::Listen()
		{
			ASSERT(m_hSocket != NULL);
			if (listen(m_hSocket, 5) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Listening on socket");
			}
		}

		BOOL CBlockingSocket_ip_4::Accept(CBlockingSocket_ip_4& sConnect, LPSOCKADDR psa)
		{
			ASSERT(m_hSocket != NULL);
			ASSERT(sConnect.m_hSocket == NULL);
			int nLengthAddr = sizeof(SOCKADDR);
			sConnect.m_hSocket = accept(m_hSocket, psa, &nLengthAddr);
			if (sConnect == INVALID_SOCKET) {
				// no exception if the listen was canceled
				if (WSAGetLastError() != WSAEINTR) {
					throw new CBlockingSocketException_ip_4(L"Receiving on socket");
				}
				return FALSE;
			}
			return TRUE;
		}

		void CBlockingSocket_ip_4::Close()
		{
			if (NULL == m_hSocket)
				return;

			if (closesocket(m_hSocket) == SOCKET_ERROR) {
				// should be OK to close if closed already
				throw new CBlockingSocketException_ip_4(L"Closing socket");
			}
			m_hSocket = NULL;
		}

		void CBlockingSocket_ip_4::Connect(LPCSOCKADDR psa)
		{
			ASSERT(m_hSocket != NULL);
			// should timeout by itself
			if (connect(m_hSocket, psa, sizeof(SOCKADDR)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Connecting");
			}
		}

		int CBlockingSocket_ip_4::Write(const char* pch, const int nSize, const int nSecs)
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

		int CBlockingSocket_ip_4::Send(const char* pch, const int nSize, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			// returned value will be less than nSize if client cancels the reading
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, NULL, &fd, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_4(L"Sending time out");
			}
			int nBytesSent;
			if ((nBytesSent = send(m_hSocket, pch, nSize, 0)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Sending");
			}
			return nBytesSent;
		}

		int CBlockingSocket_ip_4::Receive(char* pch, const int nSize, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, &fd, NULL, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_4(L"Receiving time out");
			}

			int nBytesReceived;
			if ((nBytesReceived = recv(m_hSocket, pch, nSize, 0)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Receiving");
			}
			return nBytesReceived;
		}

		int CBlockingSocket_ip_4::ReceiveDatagram(char* pch, const int nSize, LPSOCKADDR psa, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, &fd, NULL, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_4(L"Receiving time out");
			}

			// input buffer should be big enough for the entire datagram
			int nFromSize = sizeof(SOCKADDR);
			int nBytesReceived = recvfrom(m_hSocket, pch, nSize, 0, psa, &nFromSize);
			if (nBytesReceived == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Receiving datagram");
			}
			return nBytesReceived;
		}

		int CBlockingSocket_ip_4::SendDatagram(const char* pch, const int nSize, LPCSOCKADDR psa, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, NULL, &fd, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_4(L"Sending time out");
			}

			int nBytesSent = sendto(m_hSocket, pch, nSize, 0, psa, sizeof(SOCKADDR));
			if (nBytesSent == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Sending datagram");
			}
			return nBytesSent;
		}

		void CBlockingSocket_ip_4::GetPeerAddr(LPSOCKADDR psa)
		{
			ASSERT(m_hSocket != NULL);
			// gets the address of the socket at the other end
			int nLengthAddr = sizeof(SOCKADDR);
			if (getpeername(m_hSocket, psa, &nLengthAddr) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Getting remote name");
			}
		}

		void CBlockingSocket_ip_4::GetSockAddr(LPSOCKADDR psa)
		{
			ASSERT(m_hSocket != NULL);
			// gets the address of the socket at this end
			int nLengthAddr = sizeof(SOCKADDR);
			if (getsockname(m_hSocket, psa, &nLengthAddr) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_4(L"Getting name of socket");
			}
		}

		//static
		CSockAddr_ip_4 CBlockingSocket_ip_4::GetHostByName(const char* pchName, const USHORT ushPort /* = 0 */)
		{
			struct addrinfo* result = NULL;
			auto ipv4_addresses = GetAddressInformationIPv4(pchName, &result);
			if (result != NULL)
			{
				freeaddrinfo(result);
			}
			if (ipv4_addresses.size() == 0) {
				throw new CBlockingSocketException_ip_4(L"Getting address by name");
			}
			auto pulAddr = ipv4_addresses.front();
			SOCKADDR_IN sockTemp;
			sockTemp.sin_family = AF_INET;
			sockTemp.sin_port = htons(ushPort);
			sockTemp.sin_addr.s_addr = *(ULONG*)(pulAddr); // address is already in network byte order
			return sockTemp;
		}

		//static
		const char* CBlockingSocket_ip_4::GetHostByAddr(LPCSOCKADDR psa)
		{
			auto name = GetNameInformationIPv4(*(IN_ADDR*)((psa->sa_data)));
			return name;
		}

		// Class CHttpBlockingSocket
		IMPLEMENT_DYNAMIC(CHttpBlockingSocket_ip_4, CBlockingSocket_ip_4)

			CHttpBlockingSocket_ip_4::CHttpBlockingSocket_ip_4()
		{
			m_pReadBuf = new char[nSizeRecv];
			m_nReadBuf = 0;
		}

		CHttpBlockingSocket_ip_4::~CHttpBlockingSocket_ip_4()
		{
			delete[] m_pReadBuf;
		}

		int CHttpBlockingSocket_ip_4::ReadHttpHeaderLine(char* pch, const int nSize, const int nSecs)
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
					throw new CBlockingSocketException_ip_4(L"Reading header");
				}
				m_nReadBuf += nBytesThisTime;
			} while (TRUE);
			*(pch + nLineLength) = '\0';
			return nLineLength;
		}

		int CHttpBlockingSocket_ip_4::ReadHttpResponse(char* pch, const int nSize, const int nSecs)
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

		void LogBlockingSocketException(LPVOID pParam, wchar_t* pch, CBlockingSocketException_ip_4* pe)
		{	// pParam holds the HWND for the destination window (in another thread)
			CString strGmt = CTime::GetCurrentTime().FormatGmt("%m/%d/%y %H:%M:%S GMT");
			wchar_t text1[500], text2[500];
			pe->GetErrorMessage((LPWSTR)text2, 500);
			wsprintf((wchar_t*)text1, L"Networking error --%s %s -- %s\r\n", pch, text2, strGmt.GetBuffer());
			::SendMessage((HWND)pParam, EM_SETSEL, (WPARAM)65534, 65535);
			::SendMessage((HWND)pParam, EM_REPLACESEL, (WPARAM)0, (LPARAM)text1);
		}

		bool domain_name_to_internet_4_name(CStringW domain_name, CStringA& internet_name)
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

			if (DnsQuery_W(local_domain_name_unicode, DNS_TYPE_A, 0, NULL, &ppQueryResults, NULL) == ERROR_SUCCESS)
			{
				for (PDNS_RECORD ptr = ppQueryResults; ptr != NULL; ptr = ptr->pNext)
				{
					if (ptr->wType == DNS_TYPE_A)
					{
						if (ptr->wDataLength != 0)
						{
							char local_address_buffer[100];
							inet_ntop(AF_INET, &ptr->Data.A.IpAddress, local_address_buffer, 100);
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

		int lookup_addr_indx_ip_4(int indx,
			unsigned long* addr)
		{
#ifdef WIN32
			LPSOCKET_ADDRESS_LIST list = NULL;
			SOCKET  sc = 0;
			char  buf[BUF_SIZE];
			int len = 0;
			int ret = 0;

			sc = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
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
				//	found address
				if (i == indx) {
					memcpy(addr,
						&list->Address[i].lpSockaddr->sa_data[2], 4);
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
			sc = socket(AF_INET, SOCK_DGRAM, 0);
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


#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

		/* Note: could also use malloc() and free() */

		bool get_ipv4_and_mask(std::string& result)
		{

			int i;

			/* Variables used by GetIpAddrTable */
			PMIB_IPADDRTABLE pIPAddrTable;
			DWORD dwSize = 0;
			DWORD dwRetVal = 0;
			IN_ADDR IPAddr;

			/* Variables used to return error message */
			LPVOID lpMsgBuf;

			// Before calling AddIPAddress we use GetIpAddrTable to get
			// an adapter to which we can add the IP.
			pIPAddrTable = (MIB_IPADDRTABLE*)MALLOC(sizeof(MIB_IPADDRTABLE));

			if (pIPAddrTable) {
				// Make an initial call to GetIpAddrTable to get the
				// necessary size into the dwSize variable
				if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) ==
					ERROR_INSUFFICIENT_BUFFER) {
					FREE(pIPAddrTable);
					pIPAddrTable = (MIB_IPADDRTABLE*)MALLOC(dwSize);

				}
				if (pIPAddrTable == NULL) {
					//            printf("Memory allocation failed for GetIpAddrTable\n");
					return false;
				}
			}
			// Make a second call to GetIpAddrTable to get the
			// actual data we want
			if ((dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) != NO_ERROR) {
				// printf("GetIpAddrTable failed with error %d\n", dwRetVal);
				if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),       // Default language
					(LPTSTR)&lpMsgBuf, 0, NULL)) {
					//    printf("\tError: %s", lpMsgBuf);
					LocalFree(lpMsgBuf);
				}
				return false;
			}

			//printf("\tNum Entries: %ld\n", pIPAddrTable->dwNumEntries);
			if (pIPAddrTable!=nullptr)
			for (i = 0; i < (int)pIPAddrTable->dwNumEntries; i++) {
				//printf("\n\tInterface Index[%d]:\t%ld\n", i, pIPAddrTable->table[i].dwIndex);
				IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[i].dwAddr;
				//printf("\tIP Address[%d]:     \t%s\n", i, inet_ntoa(IPAddr) );
				char local_address_buffer[100];
				inet_ntop(AF_INET, &IPAddr, local_address_buffer, 100);
				result += std::string(local_address_buffer);
				IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[i].dwMask;
				//printf("\tSubnet Mask[%d]:    \t%s\n", i, inet_ntoa(IPAddr) );
				result += std::string("/");
				inet_ntop(AF_INET, &IPAddr, local_address_buffer, 100);
				result += std::string(local_address_buffer);
				result += std::string("\n");
				//IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwBCastAddr;
				/*/
				printf("\tBroadCast[%d]:      \t%s (%ld%)\n", i, inet_ntoa(IPAddr), pIPAddrTable->table[i].dwBCastAddr);
				printf("\tReassembly size[%d]:\t%ld\n", i, pIPAddrTable->table[i].dwReasmSize);
				printf("\tType and State[%d]:", i);
				if (pIPAddrTable->table[i].wType & MIB_IPADDR_PRIMARY)
					printf("\tPrimary IP Address");
				if (pIPAddrTable->table[i].wType & MIB_IPADDR_DYNAMIC)
					printf("\tDynamic IP Address");
				if (pIPAddrTable->table[i].wType & MIB_IPADDR_DISCONNECTED)
					printf("\tAddress is on disconnected interface");
				if (pIPAddrTable->table[i].wType & MIB_IPADDR_DELETED)
					printf("\tAddress is being deleted");
				if (pIPAddrTable->table[i].wType & MIB_IPADDR_TRANSIENT)
					printf("\tTransient address");
				printf("\n");
				/*/
			}

			if (pIPAddrTable) {
				FREE(pIPAddrTable);
				pIPAddrTable = NULL;
			}

			return true;
		}

		bool are_ipv4_from_one_subnet(std::string parameter_local_computer_1_ipv4, std::string parameter_computer_2_ipv4)
		{
			std::string local_result;

			if (get_ipv4_and_mask(local_result))
			{
				std::string::size_type pos_1 = local_result.find(parameter_local_computer_1_ipv4);

				if (pos_1 != std::string::npos)
				{
					//::MessageBoxA(NULL,parameter_local_computer_1_ipv4.c_str(),"Found ipv4",0);
					std::string::size_type pos_2 = local_result.find("/", pos_1);
					if (pos_2 != std::string::npos)
					{
						//::MessageBoxA(NULL,parameter_local_computer_1_ipv4.c_str(),"Found /",0);
						std::string parameter_computer_1_ipv4_mask;
						for (std::string::size_type mask_counter = pos_2 + 1; mask_counter < local_result.length(); mask_counter++)
						{
							char local_char = local_result.at(mask_counter);
							if (local_char != '\n')
							{
								parameter_computer_1_ipv4_mask += local_char;
							}
							else
							{
								break;
							}
						}

						//::MessageBoxA(NULL,CStringA(parameter_local_computer_1_ipv4.c_str()) + CStringA("/") + CStringA(parameter_computer_1_ipv4_mask.c_str()),parameter_computer_2_ipv4.c_str(),MB_ICONINFORMATION);

						if (
							(convert_ipv4_to_dword(parameter_local_computer_1_ipv4) & convert_ipv4_to_dword(parameter_computer_1_ipv4_mask))
							==
							(convert_ipv4_to_dword(parameter_computer_2_ipv4) & convert_ipv4_to_dword(parameter_computer_1_ipv4_mask))
							)
						{
							return true;
						}
					}
				}
			}
			return false;
		}

		DWORD convert_ipv4_to_dword(std::string parameter_ipv4)
		{
			BYTE b1 = 0;
			BYTE b2 = 0;
			BYTE b3 = 0;
			BYTE b4 = 0;

			std::string bs1;
			std::string bs2;
			std::string bs3;
			std::string bs4;

			std::string::size_type counter = 0;
			for (; counter < parameter_ipv4.length(); counter++)
			{
				char local_char = parameter_ipv4.at(counter);
				if (local_char != '.')
				{
					bs1 += local_char;
				}
				else
				{
					break;
				}
			}

			for (counter++; counter < parameter_ipv4.length(); counter++)
			{
				char local_char = parameter_ipv4.at(counter);
				if (local_char != '.')
				{
					bs2 += local_char;
				}
				else
				{
					break;
				}
			}
			for (counter++; counter < parameter_ipv4.length(); counter++)
			{
				char local_char = parameter_ipv4.at(counter);
				if (local_char != '.')
				{
					bs3 += local_char;
				}
				else
				{
					break;
				}
			}

			for (counter++; counter < parameter_ipv4.length(); counter++)
			{
				char local_char = parameter_ipv4.at(counter);
				if (local_char != '.')
				{
					bs4 += local_char;
				}
				else
				{
					break;
				}
			}

			b1 = atoi(bs1.c_str());
			b2 = atoi(bs2.c_str());
			b3 = atoi(bs3.c_str());
			b4 = atoi(bs4.c_str());

			return (DWORD(b1) << 24) | (DWORD(b2) << 16) | (DWORD(b3) << 8) | (DWORD(b4));
		}


		std::list<LPSOCKADDR4> GetAddressInformationIPv4(const char* pchName, struct addrinfo* *result)
		{
			std::list<LPSOCKADDR4> Results;
			CStringA Result;
			INT iRetval;

			DWORD dwRetval;

			int i = 1;

//			struct addrinfo* result = NULL;
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
						Result.Format("%s", local_buffer);
						Results.push_back(*(LPSOCKADDR4*)sockaddr_ipv4);
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
							//Results.push_back(Result);
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

		CStringA GetNameInformationIPv4(IN_ADDR parameter)
		{
			int iResult = 0;

			DWORD dwRetval;

			struct sockaddr_in saGNI;
			char hostname[NI_MAXHOST];
			char servInfo[NI_MAXSERV];
			u_short port = 27015;

			//-----------------------------------------
			// Set up sockaddr_in structure which is passed
			// to the getnameinfo function
			ZeroMemory(&saGNI, sizeof(sockaddr_in));
			saGNI.sin_family = AF_INET;
			saGNI.sin_addr = parameter;
			saGNI.sin_port = htons(port);

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
