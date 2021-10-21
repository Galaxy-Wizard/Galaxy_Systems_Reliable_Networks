// blocksock.h
#pragma once

// needs winsock.h in the precompiled headers

#include <string>
#include <list>

namespace network
{
	namespace ip_6
	{

		typedef const struct sockaddr_in6* LPSOCKADDR6;

		std::list<SOCKADDR_IN6> GetAddressInformationIPv6(const char* pchName, struct addrinfo** result);
		CStringA GetNameInformationIPv6(IN6_ADDR parameter);

		class CBlockingSocketException_ip_6 : public CException
		{
		public:
			// Constructor
			CBlockingSocketException_ip_6(wchar_t* pchMessage);

		public:
			~CBlockingSocketException_ip_6() {}
			virtual BOOL GetErrorMessage(LPWSTR lpstrError, UINT nMaxError,
				PUINT pnHelpContext = NULL);

			virtual int GetErrorNumber()
			{
				return m_nError;
			}

		private:
			int m_nError;
			CString m_strMessage;
		};

		extern void LogBlockingSocketException(LPVOID pParam, wchar_t* pch, CBlockingSocketException_ip_6* pe);

		class CSockAddr_ip_6 : public sockaddr_in6 {
		public:
			// constructors
			CSockAddr_ip_6()
			{
				ZeroMemory(this, sizeof(sockaddr_in6));
				sin6_family = AF_INET6;
				sin6_port = 0;
				sin6_addr = in6addr_any;
			} // Default
		/*/
			CSockAddr_ip_6(const SOCKADDR& sa)
			{
				ZeroMemory(this,sizeof(sockaddr_in6));
				memcpy(this, &sa, sizeof(SOCKADDR));
			}
		/*/
			CSockAddr_ip_6(const SOCKADDR_IN6& sin)
			{
				ZeroMemory(this, sizeof(sockaddr_in6));
				memcpy(this, &sin, sizeof(SOCKADDR_IN6));
			}
			CSockAddr_ip_6(const in6_addr ulAddr, const USHORT ushPort = 0) // parms are host byte ordered
			{
				ZeroMemory(this, sizeof(sockaddr_in6));
				sin6_family = AF_INET6;
				sin6_port = htons(ushPort);
				memcpy(&sin6_addr, &ulAddr, sizeof(sin6_addr));
			}
			CSockAddr_ip_6(const char* pchIP, const USHORT ushPort = 0) // dotted IP addr string
			{
				ZeroMemory(this, sizeof(sockaddr_in6));
				sin6_family = AF_INET6;
				sin6_port = htons(ushPort);
				ZeroMemory(&sin6_addr, sizeof(sin6_addr));
				INT local_result = inet_pton(AF_INET6, pchIP, &sin6_addr);
			} // already network byte ordered
			// Return the address in dotted-decimal format
			CString DottedDecimal()
			{
				char local_address_buffer[100];
				inet_ntop(AF_INET6, &sin6_addr, local_address_buffer, 100);
				return CString(local_address_buffer);
			} // constructs a new CString object
			// Get port and address (even though they're public)
			USHORT Port() const
			{
				return ntohs(sin6_port);
			}
			in6_addr IPAddr() const
			{
				return sin6_addr;
			}
			// operators added for efficiency
		/*/
			const CSockAddr_ip_6& operator=(const SOCKADDR& sa)
				{ memcpy(this, &sa, sizeof(SOCKADDR));
				  return *this; }
			const CSockAdd_ip_6r& operator=(const SOCKADDR_IN6& sin)
				{ memcpy(this, &sin, sizeof(SOCKADDR_IN6));
				  return *this; }
			operator SOCKADDR()
				{ return *((LPSOCKADDR) this); }
			operator LPSOCKADDR()
				{ return (LPSOCKADDR) this; }
		/*/
			operator LPSOCKADDR_IN6()
			{
				return (LPSOCKADDR_IN6)this;
			}
		};

		// member functions truly block and must not be used in UI threads
		// use this class as an alternative to the MFC CSocket class
		class CBlockingSocket_ip_6 : public CObject
		{
			DECLARE_DYNAMIC(CBlockingSocket_ip_6)
		public:
			SOCKET m_hSocket;
			CBlockingSocket_ip_6() { m_hSocket = NULL; }
			void Cleanup();
			void Create(int nType = SOCK_STREAM, UINT nProtocol = 0);
			void Close();
			void Bind(LPSOCKADDR6 psa);
			void Listen();
			void Connect(LPSOCKADDR6 psa);
			BOOL Accept(CBlockingSocket_ip_6& s, LPSOCKADDR6 psa);
			int Send(const char* pch, const int nSize, const int nSecs);
			int Write(const char* pch, const int nSize, const int nSecs);
			int Receive(char* pch, const int nSize, const int nSecs);
			int SendDatagram(const char* pch, const int nSize, LPSOCKADDR6 psa,
				const int nSecs);
			int ReceiveDatagram(char* pch, const int nSize, LPSOCKADDR6 psa,
				const int nSecs);
			void GetPeerAddr(LPSOCKADDR6 psa);
			void GetSockAddr(LPSOCKADDR6 psa);
			static CSockAddr_ip_6 GetHostByName(const char* pchName,
				const USHORT ushPort = 0);
			static const char* GetHostByAddr(LPSOCKADDR6 psa);
			operator SOCKET()
			{
				return m_hSocket;
			}
		};

		class CHttpBlockingSocket_ip_6 : public CBlockingSocket_ip_6
		{
		public:
			DECLARE_DYNAMIC(CHttpBlockingSocket_ip_6)
			enum { nSizeRecv = 1000 }; // max receive buffer size (> hdr line length)
			CHttpBlockingSocket_ip_6();
			~CHttpBlockingSocket_ip_6();
			int ReadHttpHeaderLine(char* pch, const int nSize, const int nSecs);
			int ReadHttpResponse(char* pch, const int nSize, const int nSecs);
		private:
			char* m_pReadBuf; // read buffer
			int m_nReadBuf; // number of bytes in the read buffer
		};

		bool domain_name_to_internet_6_name(CStringW domain_name, CStringA& internet_name);

		int lookup_addr_indx_ip_6(int indx,
			sockaddr_in6* addr);

	}
}