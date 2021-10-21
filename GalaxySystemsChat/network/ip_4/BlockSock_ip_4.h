// blocksock.h

#pragma once

// needs winsock.h in the precompiled headers

#include <string>
#include <list>

namespace network
{
	namespace ip_4
	{
		typedef const struct sockaddr* LPCSOCKADDR;
		typedef const struct sockaddr_in* LPSOCKADDR4;

		std::list<LPSOCKADDR4> GetAddressInformationIPv4(const char* pchName, struct addrinfo** result);
		CStringA GetNameInformationIPv4(IN_ADDR parameter);

		class CBlockingSocketException_ip_4 : public CException
		{
		public:
			// Constructor
			CBlockingSocketException_ip_4(wchar_t* pchMessage);

		public:
			~CBlockingSocketException_ip_4() {}
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

		extern void LogBlockingSocketException(LPVOID pParam, wchar_t* pch, CBlockingSocketException_ip_4* pe);

		class CSockAddr_ip_4 : public sockaddr_in {
		public:
			// constructors
			CSockAddr_ip_4()
			{
				sin_family = AF_INET;
				sin_port = 0;
				sin_addr.s_addr = 0;
			} // Default
			CSockAddr_ip_4(const SOCKADDR& sa) { memcpy(this, &sa, sizeof(SOCKADDR)); }
			CSockAddr_ip_4(const SOCKADDR_IN& sin) { memcpy(this, &sin, sizeof(SOCKADDR_IN)); }
			CSockAddr_ip_4(const ULONG ulAddr, const USHORT ushPort = 0) // parms are host byte ordered
			{
				sin_family = AF_INET;
				sin_port = htons(ushPort);
				sin_addr.s_addr = htonl(ulAddr);
			}
			CSockAddr_ip_4(const char* pchIP, const USHORT ushPort = 0) // dotted IP addr string
			{
				sin_family = AF_INET;
				sin_port = htons(ushPort);
				inet_pton(AF_INET, pchIP, &sin_addr.s_addr);
			} // already network byte ordered
// Return the address in dotted-decimal format
			CString DottedDecimal()
			{
				char local_address_buffer[100];
				inet_ntop(AF_INET, &sin_addr, local_address_buffer, 100);
				return CString(local_address_buffer);
			} // constructs a new CString object
			// Get port and address (even though they're public)
			USHORT Port() const
			{
				return ntohs(sin_port);
			}
			ULONG IPAddr() const
			{
				return ntohl(sin_addr.s_addr);
			}
			// operators added for efficiency
			const CSockAddr_ip_4& operator=(const SOCKADDR& sa)
			{
				memcpy(this, &sa, sizeof(SOCKADDR));
				return *this;
			}
			const CSockAddr_ip_4& operator=(const SOCKADDR_IN& sin)
			{
				memcpy(this, &sin, sizeof(SOCKADDR_IN));
				return *this;
			}
			operator SOCKADDR()
			{
				return *((LPSOCKADDR)this);
			}
			operator LPSOCKADDR()
			{
				return (LPSOCKADDR)this;
			}
			operator LPSOCKADDR_IN()
			{
				return (LPSOCKADDR_IN)this;
			}
		};

		// member functions truly block and must not be used in UI threads
		// use this class as an alternative to the MFC CSocket class
		class CBlockingSocket_ip_4 : public CObject
		{
			DECLARE_DYNAMIC(CBlockingSocket_ip_4)
		public:
			SOCKET m_hSocket;
			CBlockingSocket_ip_4() { m_hSocket = NULL; }
			void Cleanup();
			void Create(int nType = SOCK_STREAM, UINT nProtocol = 0);
			void Close();
			void Bind(LPCSOCKADDR psa);
			void Listen();
			void Connect(LPCSOCKADDR psa);
			BOOL Accept(CBlockingSocket_ip_4& s, LPSOCKADDR psa);
			int Send(const char* pch, const int nSize, const int nSecs);
			int Write(const char* pch, const int nSize, const int nSecs);
			int Receive(char* pch, const int nSize, const int nSecs);
			int SendDatagram(const char* pch, const int nSize, LPCSOCKADDR psa,
				const int nSecs);
			int ReceiveDatagram(char* pch, const int nSize, LPSOCKADDR psa,
				const int nSecs);
			void GetPeerAddr(LPSOCKADDR psa);
			void GetSockAddr(LPSOCKADDR psa);
			static CSockAddr_ip_4 GetHostByName(const char* pchName,
				const USHORT ushPort = 0);
			static const char* GetHostByAddr(LPCSOCKADDR psa);
			operator SOCKET()
			{
				return m_hSocket;
			}
		};

		class CHttpBlockingSocket_ip_4 : public CBlockingSocket_ip_4
		{
		public:
			DECLARE_DYNAMIC(CHttpBlockingSocket_ip_4)
			enum { nSizeRecv = 1000 }; // max receive buffer size (> hdr line length)
			CHttpBlockingSocket_ip_4();
			~CHttpBlockingSocket_ip_4();
			int ReadHttpHeaderLine(char* pch, const int nSize, const int nSecs);
			int ReadHttpResponse(char* pch, const int nSize, const int nSecs);
		private:
			char* m_pReadBuf; // read buffer
			int m_nReadBuf; // number of bytes in the read buffer
		};

		bool domain_name_to_internet_4_name(CStringW domain_name, CStringA& internet_name);

		int lookup_addr_indx_ip_4(int indx,
			unsigned long* addr);

		bool get_ipv4_and_mask(std::string& result);

		bool are_ipv4_from_one_subnet(std::string parameter_local_computer_1_ipv4, std::string parameter_computer_2_ipv4);

		DWORD convert_ipv4_to_dword(std::string parameter_ipv4);


	}
}