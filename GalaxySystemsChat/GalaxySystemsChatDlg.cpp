// GalaxySystemsChatDlg.cpp:
//

#include "pch.h"

#include "GalaxySystemsChat.h"
#include "GalaxySystemsChatDlg.h"
#include "DlgProxy.h"
#include "afxdialogex.h"

#include "encrypt\encrypt_xor\encrypt_xor.h"

#include "network\ip_4\BlockSock_ip_4.h"
#include "network\ip_6\BlockSock_ip_6.h"

#include "curl\curl.h"

#include "boost\asio.hpp"

#include <iostream>

//#define OPENSSL_API_COMPAT 0x10100000L
//#include "boost\asio\ssl.hpp"


//#ifdef _DEBUG
//#pragma comment (lib,"libcurl_a_debug.lib")
//#else
//#pragma comment (lib,"libcurl_a.lib")
//#endif // _DEBUG

#ifdef _DEBUG
#pragma comment (lib,"libcurl_debug.lib")
#else
#pragma comment (lib,"libcurl.lib")
#endif // _DEBUG


/*Windows Specific Additional Depenedencies*/
#pragma comment (lib,"Normaliz.lib")
#pragma comment (lib,"Ws2_32.lib")
#pragma comment (lib,"Wldap32.lib")
#pragma comment (lib,"Crypt32.lib")


#include "TabPageDialog.h"

#include "CAboutDialog.h"

#include "resource.h"

CString GetAnswerFromURL(CString pURL);

const std::wstring GalaxySystemsChatSingature(L"GalaxySystemsChat");

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

using namespace boost::asio;
using ip::tcp;


struct ClientTcp
{
	boost::asio::io_service& io_service;
	boost::asio::ip::tcp::socket socket;

	ClientTcp(boost::asio::io_service& ios, std::string const& host, std::string const& port)
		: io_service(ios), socket(io_service)
	{
		boost::asio::ip::tcp::resolver resolver(io_service);
		boost::asio::ip::tcp::resolver::query tcp_query(host, port);
		try
		{
			boost::asio::ip::tcp::resolver::iterator endpoint = resolver.resolve(tcp_query);
			boost::asio::connect(this->socket, endpoint);
		}
		catch (std::exception& e)
		{
			AfxMessageBox(CString(e.what()), MB_ICONEXCLAMATION);
		}
	};

	void send(std::vector<BYTE> const& message)
	{
		try
		{
			socket.send(boost::asio::buffer(message));
		}
		catch (std::exception& e)
		{
			AfxMessageBox(CString(e.what()), MB_ICONEXCLAMATION);
		}
	}

	~ClientTcp()
	{
		socket.close();
	}
};

struct ClientUdp
{
	boost::asio::io_service& io_service;
	boost::asio::ip::udp::socket socket;

	ClientUdp(boost::asio::io_service& ios, std::string const& host, std::string const& port)
		: io_service(ios), socket(io_service)
	{
		boost::asio::ip::udp::resolver resolver(io_service);
		boost::asio::ip::udp::resolver::query udp_query(host, port);
		try
		{
			boost::asio::ip::udp::resolver::iterator endpoint = resolver.resolve(udp_query);
			boost::asio::connect(this->socket, endpoint);
		}
		catch (std::exception& e)
		{
			AfxMessageBox(CString(e.what()), MB_ICONEXCLAMATION);
		}
	};

	void send(std::vector<BYTE> const& message)
	{
		try
		{
			socket.send(boost::asio::buffer(message));
		}
		catch (std::exception& e)
		{
			AfxMessageBox(CString(e.what()), MB_ICONEXCLAMATION);
		}
	}

	~ClientUdp()
	{
		socket.close();
	}
};



struct listen_interface_thread_parameters
{
	listen_interface_thread_parameters()
	{
		port = 0;
		dialog = nullptr;
	}
	listen_interface_thread_parameters(const listen_interface_thread_parameters& p)
	{
		ii = p.ii;
		port = p.port;
		dialog = p.dialog;
	}

	interface_information ii;
	int port;
	CGalaxySystemsChatDlg* dialog;
};

UINT __cdecl listen_interface_thread_tcp(LPVOID pParam);
UINT __cdecl listen_interface_thread_udp(LPVOID pParam);
UINT __cdecl send_interface_thread_tcp(LPVOID pParam);
UINT __cdecl send_interface_thread_udp(LPVOID pParam);


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

IMPLEMENT_DYNAMIC(CGalaxySystemsChatDlg, CDialogEx);

CGalaxySystemsChatDlg::CGalaxySystemsChatDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_GALAXYSYSTEMSCHAT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_pAutoProxy = nullptr;
}

CGalaxySystemsChatDlg::~CGalaxySystemsChatDlg()
{
	if (m_pAutoProxy != nullptr)
		m_pAutoProxy->m_pDialog = nullptr;

	for (auto i = tab_pages.begin(); i != tab_pages.end(); i++)
	{
		if (i->tab != nullptr)
		{
			delete i->tab;
			i->tab = nullptr;
		}
	}
}

void CGalaxySystemsChatDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, Combo1);
	DDX_Control(pDX, IDC_COMBO2, Combo2);
	DDX_Control(pDX, IDC_COMBO3, Combo3);
	DDX_Control(pDX, IDC_COMBO4, Combo4);
	DDX_Control(pDX, IDC_CHECK1, Check1);
	DDX_Control(pDX, IDC_CHECK2, Check2);
	DDX_Control(pDX, IDC_CHECK3, Check3);
	DDX_Control(pDX, IDC_CHECK4, Check4);
	DDX_Control(pDX, IDC_EDIT1, Edit1);
	DDX_Control(pDX, IDC_EDIT2, Edit2);
	DDX_Control(pDX, IDC_EDIT3, Edit3);
	DDX_Control(pDX, IDC_EDIT4, Edit4);
	DDX_Control(pDX, IDC_EDIT5, Edit5);
	DDX_Control(pDX, IDC_EDIT6, Edit6);
	DDX_Control(pDX, IDC_EDIT7, Edit7);
	DDX_Control(pDX, IDC_RADIO1, Radio1);
	DDX_Control(pDX, IDC_RADIO2, Radio2);
	DDX_Control(pDX, IDC_STATIC_TAB, Tab1);

	DDX_Control(pDX, IDC_RADIO3, Radio3);
	DDX_Control(pDX, IDC_RADIO4, Radio4);
	DDX_Control(pDX, IDC_EDIT8, Edit8);
	DDX_Control(pDX, IDC_CHECK5, Check5);
}

#define WM_MYMESSAGE (WM_USER + 100)

BEGIN_MESSAGE_MAP(CGalaxySystemsChatDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_CLOSE()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, OnButton1Click)		//	Listen
	ON_BN_CLICKED(IDC_BUTTON2, OnButton2Click)		//	Stop listening
	ON_BN_CLICKED(IDC_BUTTON3, OnButton3Click)		//	Select send interface
	ON_BN_CLICKED(IDC_BUTTON4, OnButton4Click)		//	Stop sending interface
	ON_BN_CLICKED(IDC_BUTTON5, OnButton5Click)		//	Send
	ON_BN_CLICKED(IDC_BUTTON6, OnButton6Click)		//	Update
	ON_BN_CLICKED(IDC_BUTTON7, OnButton7Click)		//	Load default settings

	ON_BN_CLICKED(IDC_BUTTON8, OnButton8Click)		//	Add correspondent
	ON_BN_CLICKED(IDC_BUTTON9, OnButton9Click)		//	Edit correspondent
	ON_BN_CLICKED(IDC_BUTTON10, OnButton10Click)	//	Delete correspondent
	ON_BN_CLICKED(IDC_BUTTON13, OnButton13Click)	//	Find correspondent
	ON_BN_CLICKED(IDC_BUTTON11, OnButton11Click)	//	Store correspondents
	ON_BN_CLICKED(IDC_BUTTON12, OnButton12Click)	//	Load correspondents

	ON_NOTIFY(TCN_SELCHANGING, IDC_STATIC_TAB, OnTcnSelchangingStaticTab)
	ON_NOTIFY(TCN_SELCHANGE, IDC_STATIC_TAB, OnTcnSelchangeStaticTab)
	ON_MESSAGE(WM_MYMESSAGE, CreateTab)
END_MESSAGE_MAP()


BOOL CGalaxySystemsChatDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);


	ReturnToOurNetworkDefaults();

	LoadInterfacesLists();

	/*/

	TabPageDialog* Page1 = new TabPageDialog();
	if (Page1 != nullptr)
	{
		TC_ITEMW tci;

		tci.mask = TCIF_TEXT;
		tci.iImage = -1;
		tci.pszText = L"Page 1";

		Tab1.InsertItem(0, &tci);

		tci.mask = TCIF_PARAM;
		tci.lParam = (LPARAM)Page1;
		Tab1.SetItem(0, &tci);

		if (Page1->Create(IDD_DIALOG_TAB_PAGE, &Tab1) == TRUE)
		{
			Page1->SetWindowPos(nullptr, 20, 30, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
			Page1->ShowWindow(SW_SHOW);
		}

	}

	tab_pages.push_back(Page1);

	TabPageDialog* Page2 = new TabPageDialog();
	if (Page2 != nullptr)
	{
		TC_ITEMW tci;

		tci.mask = TCIF_TEXT;
		tci.iImage = -1;
		tci.pszText = L"Page 2";

		Tab1.InsertItem(0, &tci);

		tci.mask = TCIF_PARAM;
		tci.lParam = (LPARAM)Page2;
		Tab1.SetItem(0, &tci);

		if (Page2->Create(IDD_DIALOG_TAB_PAGE, &Tab1) == TRUE)
		{
			Page2->SetWindowPos(nullptr, 20, 30, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
			Page2->ShowWindow(SW_SHOW);
		}
	}

	tab_pages.push_back(Page2);

	//*/

	/*/

	wchar_t source_string[9];
	memset(source_string, 0, 9 * sizeof(wchar_t));
	wcscpy_s(source_string, L"19811987");

	CString local_edit_text(L"Testing encryption functions");
	Edit2.SetWindowTextW(local_edit_text);


	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));




	//	1)
	encrypt::encrypt_xor((char*)source_string, 8 * sizeof(wchar_t) / sizeof(char), 0x04);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));

	encrypt::encrypt_xor(source_string, 8, 0x0404);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));




	//	2)
	encrypt::encrypt_xor(source_string, 8, 0x8187);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));

	encrypt::encrypt_xor(source_string, 8, sizeof(wchar_t), 0x8187);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));




	//	3)
	encrypt::encrypt_xor(source_string, 4, sizeof(wchar_t) * 2, 0x69428187);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));

	const unsigned char encryption_code_4[4]
		=
	{
		unsigned char('\x87'),
		unsigned char('\x81'),
		unsigned char('\x42'),
		unsigned char('\x69')
	};

	encrypt::encrypt_xor(source_string, 4, sizeof(wchar_t) / sizeof(char) * 2, (unsigned char*)encryption_code_4);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));




	//	4)
	const unsigned char encryption_code_8[8]
		=
	{
		unsigned char('\x22'),
		unsigned char('\x16'),
		unsigned char('\x81'),
		unsigned char('\x87'),
		unsigned char('\x69'),
		unsigned char('\x42'),
		unsigned char('\x81'),
		unsigned char('\x87')
	};

	encrypt::encrypt_xor(source_string, 2, sizeof(wchar_t) / sizeof(char) * 4, (unsigned char*)encryption_code_8);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));

	const unsigned char encryption_code_16[16]
		=
	{
		unsigned char('\x22'),
		unsigned char('\x16'),
		unsigned char('\x81'),
		unsigned char('\x87'),
		unsigned char('\x69'),
		unsigned char('\x42'),
		unsigned char('\x81'),
		unsigned char('\x87'),
		unsigned char('\x22'),
		unsigned char('\x16'),
		unsigned char('\x81'),
		unsigned char('\x87'),
		unsigned char('\x69'),
		unsigned char('\x42'),
		unsigned char('\x81'),
		unsigned char('\x87')
	};

	encrypt::encrypt_xor(source_string, 1, sizeof(wchar_t) / sizeof(char) * 8, (unsigned char*)encryption_code_16);

	Edit2.GetWindowTextW(local_edit_text);
	Edit2.SetWindowTextW(local_edit_text + CString(L"\r\n") + CString(source_string));

	/*/

	return TRUE;
}

void CGalaxySystemsChatDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDialog DialogAbout;
		DialogAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

void CGalaxySystemsChatDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CGalaxySystemsChatDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CGalaxySystemsChatDlg::OnClose()
{
	if (CanExit())
		CDialogEx::OnClose();
}

void CGalaxySystemsChatDlg::OnOK()
{
	if (CanExit())
		CDialogEx::OnOK();
}

void CGalaxySystemsChatDlg::OnCancel()
{
	if (CanExit())
		CDialogEx::OnCancel();
}

BOOL CGalaxySystemsChatDlg::CanExit()
{
	if (m_pAutoProxy != nullptr)
	{
		ShowWindow(SW_HIDE);
		return FALSE;
	}

	return TRUE;
}

//	Listen
void CGalaxySystemsChatDlg::OnButton1Click()
{
	//	Listen

	if (Combo1.GetCount() > 0)
	{
		CString listen_string;
		Combo1.GetLBText(Combo1.GetCurSel(), listen_string);

		std::list<interface_information>::iterator current_interface = listen_interfaces.end();

		for (auto i = listen_interfaces.begin(); i != listen_interfaces.end(); i++)
		{
			if (i->GetIp() == listen_string)
			{
				current_interface = i;
				break;
			}
		}

		if (current_interface != listen_interfaces.end())
		{
			//	Start thread

			if (!current_interface->GetThreadRunningTcp())
			{
				// TCP
				if (Check1.GetState() != 0)
				{
					listen_interface_thread_parameters* parameters = new listen_interface_thread_parameters;

					if (parameters != nullptr)
					{
						parameters->ii = *current_interface;
						parameters->dialog = this;

						CString port_string;
						Edit3.GetWindowTextW(port_string);
						parameters->port = _wtoi(port_string);

						current_interface->SetThreadToStopTcp(false);

						auto result = AfxBeginThread(listen_interface_thread_tcp, parameters);

						current_interface->SetThreadRunningTcp(true);

						current_interface->SetWinThread(result);
					}
				}
			}

			if (!current_interface->GetThreadRunningUdp())
			{
				//	UDP
				if (Check2.GetState() != 0)
				{
					listen_interface_thread_parameters* parameters = new listen_interface_thread_parameters;

					if (parameters != nullptr)
					{
						parameters->ii = *current_interface;
						parameters->dialog = this;

						CString port_string;
						Edit3.GetWindowTextW(port_string);
						parameters->port = _wtoi(port_string);

						current_interface->SetThreadToStopUdp(false);

						auto result = AfxBeginThread(listen_interface_thread_udp, parameters);

						current_interface->SetThreadRunningUdp(true);

						current_interface->SetWinThread(result);
					}
				}
			}
		}
	}
}

//	Stop listening
void CGalaxySystemsChatDlg::OnButton2Click()
{
	//	Stop listening

	if (Combo1.GetCount() > 0)
	{
		CString listen_string;
		Combo1.GetLBText(Combo1.GetCurSel(), listen_string);

		std::list<interface_information>::iterator current_interface = listen_interfaces.end();

		for (auto i = listen_interfaces.begin(); i != listen_interfaces.end(); i++)
		{
			if (i->GetIp() == listen_string)
			{
				current_interface = i;
				break;
			}
		}

		if (current_interface != listen_interfaces.end())
		{
			if (current_interface->GetThreadRunningTcp())
			{
				if (Check1.GetState() != 0)
				{
					current_interface->SetThreadToStopTcp(true);
				}
			}
		}

		if (current_interface != listen_interfaces.end())
		{
			if (current_interface->GetThreadRunningUdp())
			{
				if (Check2.GetState() != 0)
				{
					current_interface->SetThreadToStopUdp(true);
				}
			}
		}
	}
}

//	Select send interface
void CGalaxySystemsChatDlg::OnButton3Click()
{

}

//	Stop sending interface
void CGalaxySystemsChatDlg::OnButton4Click()
{

}

//	Send
void CGalaxySystemsChatDlg::OnButton5Click()
{
	CString SourceInterface;
	CString SourcePort;

	CString Message;

	CString Correspondent;

	Combo2.GetWindowTextW(SourceInterface);
	Edit5.GetWindowTextW(SourcePort);

	Edit1.GetWindowTextW(Message);

	Combo3.GetWindowTextW(Correspondent);

	CString XorCode;

	Edit4.GetWindowTextW(XorCode);

	CString Name;

	Edit8.GetWindowTextW(Name);

	CString ProtocolName;

	CString Address;

	CString Port;

	for (int counter = 0; counter < Correspondent.GetLength(); counter++)
	{
		//correspondent line format: "Protocol %s Address %s Port %d";

		if (Correspondent.Find(L"Protocol", 0) == -1)
		{
			return;
		}

		if (Correspondent.Find(L"Address", 0) == -1)
		{
			return;
		}

		if (Correspondent.Find(L"Port", 0) == -1)
		{
			return;
		}

		if ((counter = Correspondent.Find(L" ", counter)) == -1)
		{
			return;
		}
		else
		{
			counter++;

			for (; counter < Correspondent.GetLength(); counter++)
			{
				auto Symbol = Correspondent.GetAt(counter);
				if (Symbol != L' ')
				{
					ProtocolName += Symbol;
				}
				else
				{
					break;
				}
			}

			counter++;

			if ((counter = Correspondent.Find(L" ", counter)) == -1)
			{
				return;
			}

			counter++;

			for (; counter < Correspondent.GetLength(); counter++)
			{
				auto Symbol = Correspondent.GetAt(counter);
				if (Symbol != L' ')
				{
					Address += Symbol;
				}
				else
				{
					break;
				}
			}

			counter++;

			if ((counter = Correspondent.Find(L" ", counter)) == -1)
			{
				return;
			}

			counter++;

			for (; counter < Correspondent.GetLength(); counter++)
			{
				auto Symbol = Correspondent.GetAt(counter);
				if (Symbol != L' ')
				{
					Port += Symbol;
				}
				else
				{
					break;
				}
			}

			break;
		}

		break;
	}

	std::wstring message = GalaxySystemsChatSingature + CString(L"Message from '").GetBuffer() + Name.GetBuffer() + CString(L"': ").GetBuffer() + Message.GetBuffer();

	auto message_size = message.length() * sizeof(wchar_t);

	unsigned char* encrypted_message = new unsigned char[message_size + sizeof(wchar_t)];

	if (encrypted_message != nullptr)
	{
		ZeroMemory(encrypted_message, message_size + sizeof(wchar_t));

		for (size_t counter = 0; counter < message.length(); counter++)
		{
			wchar_t symbol = message.at(counter);

			auto high_byte = unsigned char(symbol >> 8);
			auto low_byte = unsigned char(symbol & 0x00FF);

			encrypted_message[counter * sizeof(wchar_t) + 1] = high_byte;
			encrypted_message[counter * sizeof(wchar_t) + 0] = low_byte;
		}

		size_t atom_data_size = XorCode.GetLength() * sizeof(wchar_t);

		unsigned char* xor_code = new unsigned char[atom_data_size];

		if (xor_code != nullptr)
		{
			ZeroMemory(xor_code, atom_data_size);

			for (int counter = 0; counter < XorCode.GetLength(); counter++)
			{
				wchar_t symbol = XorCode.GetAt(counter);

				auto high_byte = unsigned char(symbol >> 8);
				auto low_byte = unsigned char(symbol & 0x00FF);

				xor_code[counter * sizeof(wchar_t) + 1] = high_byte;
				xor_code[counter * sizeof(wchar_t) + 0] = low_byte;
			}

			encrypt::encrypt_xor(encrypted_message, message_size, atom_data_size, xor_code);


			std::vector<BYTE> message;

			for (size_t counter = 0; counter < message_size; counter++)
			{
				BYTE symbol = encrypted_message[counter];

				message.push_back(symbol);
			}

			if (Check5.GetState() != 0)
			{
				Address = ResolveUniveralNamingSystem(Address);
			}

			std::string address(CStringA(Address).GetBuffer());
			std::string port(CStringA(Port).GetBuffer());

			if (ProtocolName == CString(L"TCP"))
			{
				boost::asio::io_service ios;

				ClientTcp client(ios, address, port);

				client.send(message);
			}

			if (ProtocolName == CString(L"UDP"))
			{
				boost::asio::io_service ios;

				ClientUdp client(ios, address, port);

				client.send(message);
			}

			delete[] xor_code;
		}

		delete[] encrypted_message;
	}
}

//	Update
void CGalaxySystemsChatDlg::OnButton6Click()
{
	//	Enumerate IPv4 and IPv6 interfaces

	while (Combo1.GetCount() != 0)
	{
		Combo1.DeleteString(0);
		Combo2.DeleteString(0);
	}

	if (Check3.GetState() == 1)
	{
		Combo1.AddString(CString(L"0.0.0.0"));
		Combo1.AddString(CString(L"127.0.0.1"));
		Combo2.AddString(CString(L"127.0.0.1"));
	}

	if (Check4.GetState() == 1)
	{
		Combo1.AddString(CString(L"::0"));
		Combo1.AddString(CString(L"::1"));
		Combo2.AddString(CString(L"::1"));
	}

	if (Combo1.GetCount() != 0)
	{
		Combo1.SetCurSel(0);
	}

	if (Combo2.GetCount() != 0)
	{
		Combo2.SetCurSel(0);
	}

	boost::asio::io_service io_service;

	tcp::resolver resolver(io_service);
	tcp::resolver::query query(boost::asio::ip::host_name(), "");
	tcp::resolver::iterator it = resolver.resolve(query);

	while (it != tcp::resolver::iterator())
	{
		boost::asio::ip::address addr = (it++)->endpoint().address();
		if (addr.is_v4())
		{
			if (Check3.GetState() == 1)
			{
				Combo1.AddString(CString(addr.to_string().c_str()));
				Combo2.AddString(CString(addr.to_string().c_str()));
			}
		}
		else
		{
			if (addr.is_v6())
			{
				if (Check4.GetState() == 1)
				{
					Combo1.AddString(CString(addr.to_string().c_str()));
					Combo2.AddString(CString(addr.to_string().c_str()));
				}
			}
		}
	}
}

void CGalaxySystemsChatDlg::ReturnToOurNetworkDefaults()
{
	Radio1.SetCheck(0);
	Radio2.SetCheck(1);
	Radio3.SetCheck(0);
	Radio4.SetCheck(1);

	Check1.SetCheck(0);
	Check2.SetCheck(1);
	Check3.SetCheck(1);
	Check4.SetCheck(1);

	Edit3.SetWindowTextW(CString(L"6942"));
	Edit4.SetWindowTextW(CString(L"8187"));
	Edit5.SetWindowTextW(CString(L"4269"));


	while (Combo4.GetCount() != 0)
	{
		Combo4.DeleteString(0);
	}

	Combo4.AddString(CString(L"1 Byte"));
	Combo4.AddString(CString(L"2 Bytes"));
	Combo4.AddString(CString(L"3 Bytes"));
	Combo4.AddString(CString(L"4 Bytes"));
	Combo4.AddString(CString(L"5 Bytes"));
	Combo4.AddString(CString(L"6 Bytes"));
	Combo4.AddString(CString(L"7 Bytes"));
	Combo4.AddString(CString(L"8 Bytes"));
	Combo4.AddString(CString(L"9 Bytes"));
	Combo4.AddString(CString(L"10 Bytes"));

	Combo4.SetCurSel(1);
}

//	Load default settings
void CGalaxySystemsChatDlg::OnButton7Click()
{
	ReturnToOurNetworkDefaults();
}

void CGalaxySystemsChatDlg::LoadInterfacesLists()
{
	//	Enumerate IPv4 and IPv6 interfaces

	listen_interfaces.clear();
	send_interfaces.clear();

	listen_interfaces.push_back(interface_information(CString(L"0.0.0.0"), false, false, nullptr));
	listen_interfaces.push_back(interface_information(CString(L"127.0.0.1"), false, false, nullptr));
	send_interfaces.push_back(interface_information(CString(L"127.0.0.1"), false, false, nullptr));

	listen_interfaces.push_back(interface_information(CString(L"::0"), false, false, nullptr));
	listen_interfaces.push_back(interface_information(CString(L"::1"), false, false, nullptr));
	send_interfaces.push_back(interface_information(CString(L"::1"), false, false, nullptr));

	using boost::asio::ip::tcp;
	boost::asio::io_service io_service;

	tcp::resolver resolver(io_service);
	tcp::resolver::query query(boost::asio::ip::host_name(), "");
	tcp::resolver::iterator it = resolver.resolve(query);

	while (it != tcp::resolver::iterator())
	{
		boost::asio::ip::address addr = (it++)->endpoint().address();
		if (addr.is_v4())
		{
			listen_interfaces.push_back(interface_information(CString(addr.to_string().c_str()), false, false, nullptr));
			send_interfaces.push_back(interface_information(CString(addr.to_string().c_str()), false, false, nullptr));
		}
		else
		{
			if (addr.is_v6())
			{
				listen_interfaces.push_back(interface_information(CString(addr.to_string().c_str()), false, false, nullptr));
				send_interfaces.push_back(interface_information(CString(addr.to_string().c_str()), false, false, nullptr));
			}
		}
	}
}


void read_handler(const boost::system::error_code& error, std::size_t bytes_transferred)
{
}

void wait_handler(const boost::system::error_code& error)
{
}

std::vector<BYTE> receive_tcp(tcp::socket& socket)
{
	const size_t CONST_BUFFER_SIZE = 500;
	BYTE buf[CONST_BUFFER_SIZE];
	memset(buf, 0, CONST_BUFFER_SIZE);

	size_t received_bytes = socket.receive(buffer(buf));

	std::vector<BYTE> data;

	for (size_t counter = 0; counter < received_bytes; counter++)
	{
		data.push_back(buf[counter]);
	}

	return data;
}

void send_tcp(tcp::socket& socket, const std::wstring& message)
{
	const std::wstring msg = message;
	socket.send(buffer(message));
}

std::vector<BYTE> receive_udp(udp::socket& socket, udp::endpoint& socket_remote_endpoint)
{
	const size_t CONST_BUFFER_SIZE = 500;
	BYTE buf[CONST_BUFFER_SIZE];
	memset(buf, 0, CONST_BUFFER_SIZE);

	size_t received_bytes = socket.receive_from(boost::asio::buffer(buf), socket_remote_endpoint);

	std::vector<BYTE> data;

	for (size_t counter = 0; counter < received_bytes; counter++)
	{
		data.push_back(buf[counter]);
	}

	return data;
}

void send_udp(udp::socket& socket, const std::wstring& message, ip::udp::endpoint receiver_end_point)
{
	const std::wstring msg = message;
	socket.send_to(boost::asio::buffer(message), receiver_end_point);
}


UINT __cdecl listen_interface_thread_tcp(LPVOID pParam)
{
	if (pParam == nullptr)
	{
		return 1;
	}

	listen_interface_thread_parameters* parameters = (listen_interface_thread_parameters*)pParam;

	auto dialog = parameters->dialog;
	auto ii = parameters->ii;

	if (dialog != nullptr)
	{

		bool exit_thread = false;

		auto current_interface = dialog->listen_interfaces.end();

		for (;;)
		{

			boost::asio::io_service io_service;

			//listen for new connection
			tcp::acceptor acceptor_(io_service, tcp::endpoint(ip::address::from_string(CStringA(ii.GetIp())), parameters->port));

			//socket creation 
			tcp::socket socket_(io_service);

			//waiting for connection
			acceptor_.accept(socket_);

			socket_.set_option(boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_RCVTIMEO>{ 500 });


			try
			{
				//read operation
				std::vector<BYTE> message = receive_tcp(socket_);

				if (message.size() != 0)
				{
					if (message.size() > GalaxySystemsChatSingature.length())
					{
						std::wstring message_test;
						for (size_t counter = 0; counter < GalaxySystemsChatSingature.length(); counter++)
						{
							message_test += message.at(counter);
						}


						auto xor_code_size = dialog->Combo4.GetCurSel() + 1;
						CString xor_code_string;
						dialog->Edit4.GetWindowTextW(xor_code_string);

						size_t atom_data_size = xor_code_string.GetLength() * sizeof(wchar_t);

						unsigned char* xor_code = new unsigned char[atom_data_size];

						if (xor_code != nullptr)
						{
							ZeroMemory(xor_code, atom_data_size);

							for (int counter = 0; counter < xor_code_string.GetLength(); counter++)
							{
								wchar_t symbol = xor_code_string.GetAt(counter);

								auto high_byte = unsigned char(symbol >> 8);
								auto low_byte = unsigned char(symbol & 0x00FF);

								xor_code[counter * sizeof(wchar_t) + 1] = high_byte;
								xor_code[counter * sizeof(wchar_t) + 0] = low_byte;
							}

							auto message_size = message.size();
							auto message_to_xor = new BYTE[message_size + sizeof(wchar_t)];

							if (message_to_xor != nullptr)
							{
								memset(message_to_xor, 0, message_size + sizeof(wchar_t));

								for (size_t counter = 0; counter < message_size; counter++)
								{
									message_to_xor[counter] = message.at(counter);
								}

								encrypt::encrypt_xor((void*)message_to_xor, message_size, atom_data_size, xor_code);

								message_test.assign((wchar_t*)message_to_xor);

								delete[]message_to_xor;
							}

							if (message_test.substr(0, GalaxySystemsChatSingature.length()) == GalaxySystemsChatSingature)
							{
								std::wstring message_to_show;
								message_to_show = message_test.substr(GalaxySystemsChatSingature.length());

								auto socket_remote_endpoint = socket_.remote_endpoint();

								std::string CurrentTabName;
								CurrentTabName += "TCP ";

								CurrentTabName += "Address ";

								CurrentTabName += socket_remote_endpoint.address().to_string();
								//CurrentTabName += " ";
								//char buffer[20];
								//memset(buffer, 0, 20 * sizeof(char));
								//CurrentTabName += _itoa_s(socket_remote_endpoint.port(), buffer, 20, 10);

								dialog->SendMessage(WM_MYMESSAGE, reinterpret_cast<WPARAM>(&CurrentTabName), reinterpret_cast<LPARAM>(&message_to_show));

								//CString current_chat_text;
								//dialog->Edit2.GetWindowTextW(current_chat_text);

								//current_chat_text += message_to_show.c_str();
								//current_chat_text += L"\r\n";
								//dialog->Edit2.SetWindowTextW(current_chat_text);
							}

							delete[] xor_code;
						}
					}
				}
			}
			catch (std::exception& e)
			{
				auto error_message = e.what();

				/*/
				CString current_chat_text;
				dialog->Edit2.GetWindowTextW(current_chat_text);

				current_chat_text += e.what() + CString(L"\r\n");
				dialog->Edit2.SetWindowTextW(current_chat_text);
				//*/
			}

			if (socket_.is_open())
			{
				socket_.close();
			}

			for (auto i = dialog->listen_interfaces.begin(); i != dialog->listen_interfaces.end(); i++)
			{
				if (i->GetIp() == ii.GetIp())
				{
					if (i->GetThreadToStopTcp())
					{
						current_interface = i;
						exit_thread = true;
						break;
					}
				}
			}

			Sleep(1);

			if (current_interface != dialog->listen_interfaces.end())
			{
				current_interface->SetThreadRunningTcp(false);
			}

			if (exit_thread)
			{
				break;
			}
		}
	}

	delete pParam;

	return 0;
}

UINT __cdecl listen_interface_thread_udp(LPVOID pParam)
{
	if (pParam == nullptr)
	{
		return 1;
	}

	listen_interface_thread_parameters* parameters = (listen_interface_thread_parameters*)pParam;

	auto dialog = parameters->dialog;
	auto ii = parameters->ii;

	if (dialog != nullptr)
	{

		bool exit_thread = false;

		auto current_interface = dialog->listen_interfaces.end();


		boost::asio::io_service io_service;

		boost::asio::ip::udp::socket socket_(io_service);


		if (boost::asio::ip::address::from_string(CStringA(ii.GetIp())).is_v4())
		{
			socket_.open(ip::udp::v4());
		}
		else
		{
			if (boost::asio::ip::address::from_string(CStringA(ii.GetIp())).is_v6())
			{
				socket_.open(ip::udp::v6());
			}
		}

		socket_.bind(udp::endpoint(boost::asio::ip::address::from_string(CStringA(ii.GetIp())), parameters->port));

		socket_.set_option(boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_RCVTIMEO>{ 500 });

		for (;;)
		{
			try
			{
				udp::endpoint socket_remote_endpoint;
				//read operation
				std::vector<BYTE> message = receive_udp(socket_, socket_remote_endpoint);

				if (message.size() != 0)
				{
					if (message.size() > GalaxySystemsChatSingature.length())
					{
						std::wstring message_test;
						for (size_t counter = 0; counter < GalaxySystemsChatSingature.length(); counter++)
						{
							message_test += message.at(counter);
						}


						auto xor_code_size = dialog->Combo4.GetCurSel() + 1;
						CString xor_code_string;
						dialog->Edit4.GetWindowTextW(xor_code_string);

						size_t atom_data_size = xor_code_string.GetLength() * sizeof(wchar_t);

						unsigned char* xor_code = new unsigned char[atom_data_size];

						if (xor_code != nullptr)
						{
							ZeroMemory(xor_code, atom_data_size);

							for (int counter = 0; counter < xor_code_string.GetLength(); counter++)
							{
								wchar_t symbol = xor_code_string.GetAt(counter);

								auto high_byte = unsigned char(symbol >> 8);
								auto low_byte = unsigned char(symbol & 0x00FF);

								xor_code[counter * sizeof(wchar_t) + 1] = high_byte;
								xor_code[counter * sizeof(wchar_t) + 0] = low_byte;
							}

							auto message_size = message.size();
							auto message_to_xor = new BYTE[message_size + sizeof(wchar_t)];

							if (message_to_xor != nullptr)
							{
								memset(message_to_xor, 0, message_size + sizeof(wchar_t));

								for (size_t counter = 0; counter < message_size; counter++)
								{
									message_to_xor[counter] = message.at(counter);
								}

								encrypt::encrypt_xor((void*)message_to_xor, message_size, atom_data_size, xor_code);

								message_test.assign((wchar_t*)message_to_xor);

								delete[]message_to_xor;
							}


							if (message_test.substr(0, GalaxySystemsChatSingature.length()) == GalaxySystemsChatSingature)
							{
								std::wstring message_to_show;
								message_to_show = message_test.substr(GalaxySystemsChatSingature.length());

								std::string CurrentTabName;
								CurrentTabName += "UDP ";

								CurrentTabName += "Address ";

								CurrentTabName += socket_remote_endpoint.address().to_string();
								//CurrentTabName += " ";
								//char buffer[20];
								//memset(buffer, 0, 20 * sizeof(char));
								//_itoa_s(socket_remote_endpoint.port(), buffer, 20, 10);

								//CurrentTabName += "Port ";

								//CurrentTabName += buffer;

								dialog->SendMessage(WM_MYMESSAGE, reinterpret_cast<WPARAM>(&CurrentTabName), reinterpret_cast<LPARAM>(&message_to_show));

								//CString current_chat_text;
								//dialog->Edit2.GetWindowTextW(current_chat_text);

								//current_chat_text += message_to_show.c_str();
								//current_chat_text += L"\r\n";
								//dialog->Edit2.SetWindowTextW(current_chat_text);
							}

							delete[] xor_code;
						}
					}
				}
			}
			catch (std::exception& e)
			{
				auto error_message = e.what();

				/*/
				CString current_chat_text;
				dialog->Edit2.GetWindowTextW(current_chat_text);

				current_chat_text += e.what() + CString(L"\r\n");
				dialog->Edit2.SetWindowTextW(current_chat_text);
				//*/
			}

			for (auto i = dialog->listen_interfaces.begin(); i != dialog->listen_interfaces.end(); i++)
			{
				if (i->GetIp() == ii.GetIp())
				{
					if (i->GetThreadToStopUdp())
					{
						current_interface = i;
						exit_thread = true;
						break;
					}
				}
			}

			Sleep(1);

			if (current_interface != dialog->listen_interfaces.end())
			{
				current_interface->SetThreadRunningUdp(false);
			}

			if (exit_thread)
			{
				break;
			}
		}

		if (socket_.is_open())
		{
			socket_.close();
		}
	}

	delete pParam;

	return 0;
}

UINT __cdecl send_interface_thread_tcp(LPVOID pParam)
{
	if (pParam == nullptr)
	{
		return 1;
	}



	delete pParam;

	return 0;
}

UINT __cdecl send_interface_thread_udp(LPVOID pParam)
{
	if (pParam == nullptr)
	{
		return 1;
	}



	delete pParam;

	return 0;
}

void CGalaxySystemsChatDlg::OnTcnSelchangingStaticTab(NMHDR* pNMHDR, LRESULT* pResult)
{
	int iTab = Tab1.GetCurSel();
	CWnd* pWnd = nullptr;
	auto tpi = tab_pages.begin();
	for (auto counter = iTab + 1; counter != 0; counter--)
	{
		if (tpi != tab_pages.end())
		{
			pWnd = tpi->tab;
			tpi++;
		}
	}

	if (pWnd != nullptr)
	{
		pWnd->ShowWindow(SW_HIDE);
	}
	*pResult = 0;
}

void CGalaxySystemsChatDlg::OnTcnSelchangeStaticTab(NMHDR* pNMHDR, LRESULT* pResult)
{
	int iTab = Tab1.GetCurSel();
	CWnd* pWnd = nullptr;
	auto tpi = tab_pages.begin();
	for (auto counter = iTab + 1; counter != 0; counter--)
	{
		if (tpi != tab_pages.end())
		{
			pWnd = tpi->tab;
			tpi++;
		}
	}

	if (pWnd != nullptr)
	{
		pWnd->ShowWindow(SW_SHOW);
	}
	*pResult = 0;
}

LRESULT CGalaxySystemsChatDlg::CreateTab(WPARAM w, LPARAM l)
{
	std::string* tab_name = reinterpret_cast<std::string*>(w);
	std::wstring* message = reinterpret_cast<std::wstring*>(l);

	if (tab_name == nullptr)
	{
		return 0;
	}

	if (message == nullptr)
	{
		return 0;
	}

	bool add_tab = true;

	for (auto tab_pages_iterator = tab_pages.begin(); tab_pages_iterator != tab_pages.end(); tab_pages_iterator++)
	{
		auto tp = *tab_pages_iterator;
		if (tp.tab != nullptr)
		{
			if (tp.tab_name == CString(tab_name->c_str()))
			{
				add_tab = false;
			}
		}
	}

	if (add_tab)
	{
		TabPageDialog* Page = new TabPageDialog();
		if (Page != nullptr)
		{
			TC_ITEMW tci;

			tci.mask = TCIF_TEXT | TCIF_PARAM;
			tci.lParam = tab_pages.size();
			CString PageName(tab_name->c_str());
			tci.pszText = PageName.GetBuffer();

			Tab1.InsertItem(int(tci.lParam), &tci);

			if (Page->Create(IDD_DIALOG_TAB_PAGE, &Tab1) == TRUE)
			{
				Page->SetWindowTextW(PageName);
				Page->SetWindowPos(nullptr, 20, 30, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
				Page->ShowWindow(SW_SHOW);
			}

			PageStructure page_structure;
			page_structure.tab = Page;
			page_structure.tab_name = CString(tab_name->c_str());

			tab_pages.push_back(page_structure);

			Tab1.SetCurSel(int(tci.lParam));
		}
	}

	for (auto tab_pages_iterator = tab_pages.begin(); tab_pages_iterator != tab_pages.end(); tab_pages_iterator++)
	{
		auto tp = *tab_pages_iterator;
		if (tp.tab != nullptr)
		{
			if (tp.tab_name == CString(tab_name->c_str()))
			{
				CString private_chat_text;
				tp.tab->PrivateChat.GetWindowTextW(private_chat_text);

				CTime current_time = CTime::GetCurrentTime();
				CString time_string = current_time.Format(L"%A, %B %d, %Y %H:%M:%S");

				private_chat_text += L"Incoming message on " + time_string;
				private_chat_text += L" ";
				private_chat_text += L"\"";

				private_chat_text += message->c_str();

				//private_chat_text += message->c_str();
				private_chat_text += L"\"";
				private_chat_text += L"\r\n";

				tp.tab->PrivateChat.SetWindowTextW(private_chat_text);
			}
		}
	}

	return 0;
}




//	Add correspondent
void CGalaxySystemsChatDlg::OnButton8Click()
{
	//	Add
	//AfxMessageBox(L"Add");

	Correspondent correspondent;

	CString Address;
	CString PortText;
	CString Protocol;

	Edit6.GetWindowTextW(Address);
	Edit7.GetWindowTextW(PortText);

	if (Radio3.GetCheck() > 0)
	{
		Protocol = CString(L"TCP");
	}

	if (Radio4.GetCheck() > 0)
	{
		Protocol = CString(L"UDP");
	}

	WORD Port = 0;

	Port = _wtoi(PortText.GetBuffer());

	correspondent.SetAddress(Address);
	correspondent.SetPort(Port);
	correspondent.SetProtocol(Protocol);

	for (auto current = correspondents.begin(); current != correspondents.end(); current++)
	{
		if (current->GetAddress() == correspondent.GetAddress() && current->GetPort() == correspondent.GetPort() && current->GetProtocol() == correspondent.GetProtocol())
		{
			return; //	correspondent already is in list
		}
	}

	CString correspondent_line;

	correspondent_line.Format(L"Protocol %s Address %s Port %d", correspondent.GetProtocol().GetBuffer(), correspondent.GetAddress().GetBuffer(), int(correspondent.GetPort()));

	Combo3.AddString(correspondent_line);

	correspondents.push_back(correspondent);
}


//	Edit correspondent
void CGalaxySystemsChatDlg::OnButton9Click()
{
	//	Edit
	//	AfxMessageBox(L"Edit");

	//	Find and delete

	{
		Correspondent correspondent;

		CString correspondent_line;

		Combo3.GetWindowTextW(correspondent_line);

		int position_1 = correspondent_line.Find(L" ");

		if (position_1 != -1)
		{
			int position_2 = correspondent_line.Find(L" ", position_1 + 1);

			CString protocol;

			for (auto counter = position_1; counter < position_2; counter++)
			{
				protocol += correspondent_line.GetAt(counter);
			}

			position_1 = correspondent_line.Find(L" ", position_2 + 1);

			if (position_1 != -1)
			{
				position_2 = correspondent_line.Find(L" ", position_1 + 1);

				CString address;

				for (auto counter = position_1; counter < position_2; counter++)
				{
					address += correspondent_line.GetAt(counter);
				}

				position_1 = correspondent_line.Find(L" ", position_2 + 1);

				if (position_1 != -1)
				{
					position_2 = correspondent_line.GetLength();

					CString port;

					for (auto counter = position_1; counter < position_2; counter++)
					{
						port += correspondent_line.GetAt(counter);
					}

					auto port_number = _wtoi(port.GetBuffer());

					correspondent.SetProtocol(protocol);
					correspondent.SetAddress(address);
					correspondent.SetPort(port_number);

					Combo3.DeleteString(Combo3.FindString(0, correspondent_line));
				}
			}
		}

		for (auto current = correspondents.begin(); current != correspondents.end(); current++)
		{
			if (current->GetAddress() == correspondent.GetAddress() && current->GetPort() == correspondent.GetPort() && current->GetProtocol() == correspondent.GetProtocol())
			{
				correspondents.erase(current); //	found correspondent in list
			}
		}
	}

	//	Add

	Correspondent correspondent;

	CString Address;
	CString PortText;
	CString Protocol;

	Edit6.GetWindowTextW(Address);
	Edit7.GetWindowTextW(PortText);

	if (Radio3.GetCheck() > 0)
	{
		Protocol = CString(L"TCP");
	}

	if (Radio4.GetCheck() > 0)
	{
		Protocol = CString(L"UDP");
	}

	WORD Port = 0;

	Port = _wtoi(PortText.GetBuffer());

	correspondent.SetAddress(Address);
	correspondent.SetPort(Port);
	correspondent.SetProtocol(Protocol);

	for (auto current = correspondents.begin(); current != correspondents.end(); current++)
	{
		if (current->GetAddress() == correspondent.GetAddress() && current->GetPort() == correspondent.GetPort() && current->GetProtocol() == correspondent.GetProtocol())
		{
			return; //	correspondent already is in list
		}
	}

	CString correspondent_line;

	correspondent_line.Format(L"Protocol %s Address %s Port %d", correspondent.GetProtocol().GetBuffer(), correspondent.GetAddress().GetBuffer(), int(correspondent.GetPort()));

	Combo3.AddString(correspondent_line);

	correspondents.push_back(correspondent);
}


//	Delete correspondent
void CGalaxySystemsChatDlg::OnButton10Click()
{
	//	Delete
	//	AfxMessageBox(L"Delete");

	{
		Correspondent correspondent;

		CString correspondent_line;

		Combo3.GetWindowTextW(correspondent_line);

		int position_1 = correspondent_line.Find(L" ");

		if (position_1 != -1)
		{
			int position_2 = correspondent_line.Find(L" ", position_1 + 1);

			CString protocol;

			for (auto counter = position_1; counter < position_2; counter++)
			{
				protocol += correspondent_line.GetAt(counter);
			}

			position_1 = correspondent_line.Find(L" ", position_2 + 1);

			if (position_1 != -1)
			{
				position_2 = correspondent_line.Find(L" ", position_1 + 1);

				CString address;

				for (auto counter = position_1; counter < position_2; counter++)
				{
					address += correspondent_line.GetAt(counter);
				}

				position_1 = correspondent_line.Find(L" ", position_2 + 1);

				if (position_1 != -1)
				{
					position_2 = correspondent_line.GetLength();

					CString port;

					for (auto counter = position_1; counter < position_2; counter++)
					{
						port += correspondent_line.GetAt(counter);
					}

					auto port_number = _wtoi(port.GetBuffer());

					correspondent.SetProtocol(protocol);
					correspondent.SetAddress(address);
					correspondent.SetPort(port_number);

					Combo3.DeleteString(Combo3.FindString(0, correspondent_line));
				}
			}
		}

		for (auto current = correspondents.begin(); current != correspondents.end(); current++)
		{
			if (current->GetAddress() == correspondent.GetAddress() && current->GetPort() == correspondent.GetPort() && current->GetProtocol() == correspondent.GetProtocol())
			{
				correspondents.erase(current); //	found correspondent in list
			}
		}
	}
}


//	Find correspondent
void CGalaxySystemsChatDlg::OnButton13Click()
{
	//	Find
	AfxMessageBox(L"Find");
}


//	Store correspondents
void CGalaxySystemsChatDlg::OnButton11Click()
{
	//	Store
	AfxMessageBox(L"Store");
}


//	Load correspondents
void CGalaxySystemsChatDlg::OnButton12Click()
{
	//	Load
	AfxMessageBox(L"Load");
}

//	Resolve UNS
CString ResolveUniveralNamingSystem(CString pUNS, CString ServerUNS)
{
	CString Result;

	CString Request = ServerUNS + pUNS;

	CString Answer = GetAnswerFromURL(Request);

	//local.dns.uns

	if (Answer.GetLength() == 0)
	{
		Result = pUNS;
	}
	else
	{
		int i = 0;
		for (; i < Answer.GetLength(); i++)
		{
			wchar_t cs = Answer.GetAt(i);
			if (cs == L' ' || cs == L'\t')
			{
				break;
			}
		}
		i++;
		for (; i < Answer.GetLength(); i++)
		{
			wchar_t cs = Answer.GetAt(i);
			if (cs != L' ' && cs != L'\t')
			{
				break;
			}
		}
		i++;
		for (; i < Answer.GetLength(); i++)
		{
			wchar_t cs = Answer.GetAt(i);
			if (cs == L' ' || cs == L'\t')
			{
				break;
			}
		}
		i++;
		for (; i < Answer.GetLength(); i++)
		{
			wchar_t cs = Answer.GetAt(i);
			if (cs != L' ' && cs != L'\t')
			{
				break;
			}
		}
		for (; i < Answer.GetLength(); i++)
		{
			wchar_t cs = Answer.GetAt(i);
			if (cs == L'\n' || cs == L'\r' || cs == L'\t' || cs == L' ')
			{
				break;
			}
			Result += cs;
		}
	}

	return Result;
}

size_t writer(void* data, size_t size, size_t nmemb, void* clientp)
{
	size_t realsize = size * nmemb;
	CString* Result = (CString*)clientp;

	if (Result != nullptr)
	{
		for (int i = 0; i + 1 < realsize; i += 2)
		{
			INT16 high_byte = ((char*)data)[i];
			INT16 low_byte = ((char*)data)[i + 1];

			wchar_t cs = high_byte * 256 + low_byte;

			*Result += cs;
		}
	}
	else
	{
		return 0;
	}


	return realsize;
}

CString GetAnswerFromURL(CString pURL)
{
	CString Result;

	CURLcode res;
	CURL* curl_handle = curl_easy_init();

	if (curl_handle)
	{
		/* set url */
		curl_easy_setopt(curl_handle, CURLOPT_URL, CStringA(pURL.GetBuffer()).GetBuffer());

		/* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writer);

		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&Result);

		/* send a request */
		res = curl_easy_perform(curl_handle);

		curl_easy_cleanup(curl_handle);
	}

	//AfxMessageBox(Result);

	return Result;
}

