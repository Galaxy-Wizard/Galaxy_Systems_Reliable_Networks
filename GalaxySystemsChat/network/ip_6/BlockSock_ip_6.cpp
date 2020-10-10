// blocksock.cpp (CBlockingSocketException, CBlockingSocket, CHttpBlockingSocket)
#include "..\..\pch.h"

#include "blocksock_ip_6.h"

#include <list>


namespace network
{
	namespace ip_6
	{

#pragma comment (lib, "Ws2_32.lib")

#pragma comment (lib, "Normaliz.lib")

#pragma comment (lib, "dnsapi.lib")

		// Class CBlockingSocketException
		IMPLEMENT_DYNAMIC(CBlockingSocketException_ip_6, CException)

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
				wsprintf((LPWSTR)text, _T("%s: ошибка"), m_strMessage.GetBuffer());
			}
			else {
				wsprintf((LPWSTR)text, _T("%s: ошибка #%d"), m_strMessage.GetBuffer(), m_nError);
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
				throw new CBlockingSocketException_ip_6(L"Создание сокета");
			}
		}

		void CBlockingSocket_ip_6::Bind(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			if (bind(m_hSocket, (sockaddr*)psa, sizeof(sockaddr_in6)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Привязка сокета");
			}
		}

		void CBlockingSocket_ip_6::Listen()
		{
			ASSERT(m_hSocket != NULL);
			if (listen(m_hSocket, 5) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Прослушивание на сокете");
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
					throw new CBlockingSocketException_ip_6(L"Приём на сокете");
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
				throw new CBlockingSocketException_ip_6(L"Закрытие сокета");
			}
			m_hSocket = NULL;
		}

		void CBlockingSocket_ip_6::Connect(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			// should timeout by itself
			if (connect(m_hSocket, (sockaddr*)psa, sizeof(sockaddr_in6)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Соединение");
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
				throw new CBlockingSocketException_ip_6(L"Тайм аут передачи");
			}
			int nBytesSent;
			if ((nBytesSent = send(m_hSocket, pch, nSize, 0)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Передача");
			}
			return nBytesSent;
		}

		int CBlockingSocket_ip_6::Receive(char* pch, const int nSize, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, &fd, NULL, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_6(L"Тайм аут получения");
			}

			int nBytesReceived;
			if ((nBytesReceived = recv(m_hSocket, pch, nSize, 0)) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Получение");
			}
			return nBytesReceived;
		}

		int CBlockingSocket_ip_6::ReceiveDatagram(char* pch, const int nSize, LPSOCKADDR6 psa, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, &fd, NULL, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_6(L"Тайм аут получения");
			}

			// input buffer should be big enough for the entire datagram
			int nFromSize = sizeof(sockaddr_in6);
			int nBytesReceived = recvfrom(m_hSocket, pch, nSize, 0, (sockaddr*)psa, &nFromSize);
			if (nBytesReceived == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Получение датаграммы");
			}
			return nBytesReceived;
		}

		int CBlockingSocket_ip_6::SendDatagram(const char* pch, const int nSize, LPSOCKADDR6 psa, const int nSecs)
		{
			ASSERT(m_hSocket != NULL);
			FD_SET fd = { 1, m_hSocket };
			TIMEVAL tv = { nSecs, 0 };
			if (select(0, NULL, &fd, NULL, &tv) == 0) {
				throw new CBlockingSocketException_ip_6(L"Тайм аут отправки");
			}

			int nBytesSent = sendto(m_hSocket, pch, nSize, 0, (sockaddr*)psa, sizeof(sockaddr_in6));
			if (nBytesSent == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Отправка датаграммы");
			}
			return nBytesSent;
		}

		void CBlockingSocket_ip_6::GetPeerAddr(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			// gets the address of the socket at the other end
			int nLengthAddr = sizeof(sockaddr_in6);
			if (getpeername(m_hSocket, (sockaddr*)psa, &nLengthAddr) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Получение удалённого имени");
			}
		}

		void CBlockingSocket_ip_6::GetSockAddr(LPSOCKADDR6 psa)
		{
			ASSERT(m_hSocket != NULL);
			// gets the address of the socket at this end
			int nLengthAddr = sizeof(sockaddr_in6);
			if (getsockname(m_hSocket, (sockaddr*)psa, &nLengthAddr) == SOCKET_ERROR) {
				throw new CBlockingSocketException_ip_6(L"Получение имени сокета");
			}
		}

		//static
		CSockAddr_ip_6 CBlockingSocket_ip_6::GetHostByName(const char* pchName, const USHORT ushPort /* = 0 */)
		{
			char local_port[10];
			_itoa_s(ushPort, local_port, 10 - 1, 10);

			struct addrinfo hints;
			struct addrinfo* result = NULL;
			ZeroMemory(&hints, sizeof(hints));
			hints.ai_flags = AI_PASSIVE;
			hints.ai_family = AF_UNSPEC;

			DWORD dwRetval = getaddrinfo(pchName, local_port, &hints, &result);
			if (dwRetval != 0) {
				throw new CBlockingSocketException_ip_6(L"Получение адреса по имени");
			}

			SOCKADDR_IN6 sockTemp;
			memcpy(&sockTemp, result->ai_addr, sizeof(SOCKADDR_IN6)); // address is already in network byte order
			freeaddrinfo(result);
			return sockTemp;
		}

		//static
		const char* CBlockingSocket_ip_6::GetHostByAddr(LPSOCKADDR6 psa)
		{
			hostent* pHostEnt = gethostbyaddr((char*)&((LPSOCKADDR_IN6)psa)
				->sin6_addr, sizeof(((LPSOCKADDR_IN6)psa)->sin6_addr), PF_INET6);
			if (pHostEnt == NULL) {
				throw new CBlockingSocketException_ip_6(L"Получение адреса по адресу");
			}
			return pHostEnt->h_name; // caller shouldn't delete this memory
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
					throw new CBlockingSocketException_ip_6(L"Чтение заголовка");
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
			wsprintf((wchar_t*)text1, L"Сетевая ошибка --%s %s -- %s\r\n", pch, text2, strGmt.GetBuffer());
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

				wcscpy_s(local_system_error_message, local_system_error_message_size, L"IdnToAscii завершилась неудачей");

				CString local_time_string = CTime::GetCurrentTime().FormatGmt("%d/%m/%y %H:%M:%S GMT");

				wsprintf((wchar_t*)local_error_message, L"Сетевая ошибка -- %s -- %s\r\n", local_system_error_message, local_time_string.GetBuffer());

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
				//нашли адрес
				if (i == indx) {
					memcpy(addr,
						list->Address[i].lpSockaddr, list->Address[i].iSockaddrLength);
					return (1);
				}
			}
			//адресов не осталось
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

	}
}
