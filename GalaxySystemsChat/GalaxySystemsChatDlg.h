
// GalaxySystemsChatDlg.h:
//

#pragma once

#include <list>
#include <string>

#include "TabPageDialog.h"

CString ResolveUniveralNamingSystem(CString pUNS, CString ServerUNS = CString(L"https://uns.group.keenetic.link/query.php?uns="));

class interface_information
{
public:
	interface_information(CString p1, bool p2, bool p3, CWinThread* p4) : ip(p1), thread_running_tcp(p2), thread_running_udp(p3), thread(p4), thread_to_stop_tcp(false), thread_to_stop_udp(false) {}
	interface_information() : thread_running_tcp(false), thread_running_udp(false), thread(nullptr), thread_to_stop_tcp(false), thread_to_stop_udp(false) {}
	~interface_information() {}
	
	interface_information(const interface_information& p)
	{
		ip = p.ip;
		thread_running_tcp = p.thread_running_tcp;
		thread_running_udp = p.thread_running_udp;
		thread = p.thread;
		thread_to_stop_tcp = p.thread_to_stop_tcp;
		thread_to_stop_udp = p.thread_to_stop_udp;
	}

	interface_information& operator=(const interface_information& p)
	{
		ip = p.ip;
		thread_running_tcp = p.thread_running_tcp;
		thread_running_udp = p.thread_running_udp;
		thread = p.thread;
		thread_to_stop_tcp = p.thread_to_stop_tcp;
		thread_to_stop_udp = p.thread_to_stop_udp;

		return *this;
	}

	void SetIp(CString p)
	{
		ip = p;
	}

	void SetThreadRunningTcp(bool p)
	{
		thread_running_tcp = p;
	}

	void SetThreadRunningUdp(bool p)
	{
		thread_running_udp = p;
	}

	void SetWinThread(CWinThread* p)
	{
		thread = p;
	}

	void SetThreadToStopTcp(bool p)
	{
		thread_to_stop_tcp = p;
	}

	void SetThreadToStopUdp(bool p)
	{
		thread_to_stop_udp = p;
	}

	CString GetIp()
	{
		return ip;
	}

	bool GetThreadRunningTcp()
	{
		return thread_running_tcp;
	}

	bool GetThreadRunningUdp()
	{
		return thread_running_udp;
	}

	CWinThread* GetWinThread()
	{
		return thread;
	}

	bool GetThreadToStopTcp()
	{
		return thread_to_stop_tcp;
	}
	
	bool GetThreadToStopUdp()
	{
		return thread_to_stop_udp;
	}

private:
	CString ip;
	bool thread_running_tcp;
	bool thread_running_udp;
	CWinThread* thread;
	bool thread_to_stop_tcp;
	bool thread_to_stop_udp;
};

class CGalaxySystemsChatDlgAutoProxy;

class Correspondent
{
public:
	Correspondent() : address(), port(0) {}

	void SetAddress(CString p) { address = p; }
	CString GetAddress() { return address; }

	void SetPort(WORD p) { port = p; }
	WORD GetPort() { return port; }

	void SetProtocol(CString p) { protocol = p; }
	CString GetProtocol() { return protocol; }
private:
	CString protocol;
	CString address;
	WORD port;
};

// CGalaxySystemsChatDlg
class CGalaxySystemsChatDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CGalaxySystemsChatDlg);
	friend class CGalaxySystemsChatDlgAutoProxy;

public:
	CGalaxySystemsChatDlg(CWnd* pParent = nullptr);
	virtual ~CGalaxySystemsChatDlg();

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_GALAXYSYSTEMSCHAT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);

protected:
	CGalaxySystemsChatDlgAutoProxy* m_pAutoProxy;
	HICON m_hIcon;

	BOOL CanExit();

	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClose();
	virtual void OnOK();
	virtual void OnCancel();

	afx_msg void OnButton1Click();		//	Listen
	afx_msg void OnButton2Click();		//	Stop listening
	afx_msg void OnButton3Click();		//	Select send interface
	afx_msg void OnButton4Click();		//	Stop sending interface
	afx_msg void OnButton5Click();		//	Send
	afx_msg void OnButton6Click();		//	Update
	afx_msg void OnButton7Click();		//	Load default settings

	afx_msg void OnButton8Click();		//	Add correspondent
	afx_msg void OnButton9Click();		//	Edit correspondent
	afx_msg void OnButton10Click();		//	Delete correspondent
	afx_msg void OnButton13Click();		//	Find correspondent
	afx_msg void OnButton11Click();		//	Store correspondents
	afx_msg void OnButton12Click();		//	Load correspondents

	DECLARE_MESSAGE_MAP()
public:
	
	CComboBox Combo1;
	CComboBox Combo2;
	CComboBox Combo3;
	CComboBox Combo4;
	
	CButton Check1;
	CButton Check2;
	CButton Check3;
	CButton Check4;
	CButton Check5;

	CEdit Edit1;
	CEdit Edit2;
	CEdit Edit3;
	CEdit Edit4;
	CEdit Edit5;
	CEdit Edit6;
	CEdit Edit7;
	CEdit Edit8;

	CButton Radio1;
	CButton Radio2;
	CButton Radio3;
	CButton Radio4;

	CTabCtrl Tab1;

	std::list<interface_information> listen_interfaces;
	std::list<interface_information> send_interfaces;

	std::list<Correspondent> correspondents;

	struct PageStructure
	{
		PageStructure() : tab(nullptr) {}

		TabPageDialog* tab;
		CString tab_name;
	};

	std::list<PageStructure> tab_pages;

	void ReturnToOurNetworkDefaults();
	void LoadInterfacesLists();

	afx_msg LRESULT CreateTab(WPARAM w, LPARAM l);

	afx_msg void OnTcnSelchangingStaticTab(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnTcnSelchangeStaticTab(NMHDR* pNMHDR, LRESULT* pResult);
};
