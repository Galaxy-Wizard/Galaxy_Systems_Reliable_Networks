#pragma once


// CTabPageDialog dialog

class TabPageDialog : public CDialogEx
{
	DECLARE_DYNAMIC(TabPageDialog)

public:
	TabPageDialog(CWnd* pParent = nullptr);   // standard constructor
	virtual ~TabPageDialog();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_TAB_PAGE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	CEdit PrivateChat;
	CEdit PrivateAnswer;
};
