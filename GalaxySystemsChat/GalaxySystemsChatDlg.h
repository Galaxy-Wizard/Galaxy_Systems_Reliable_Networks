
// GalaxySystemsChatDlg.h: файл заголовка
//

#pragma once

class CGalaxySystemsChatDlgAutoProxy;


// Диалоговое окно CGalaxySystemsChatDlg
class CGalaxySystemsChatDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CGalaxySystemsChatDlg);
	friend class CGalaxySystemsChatDlgAutoProxy;

// Создание
public:
	CGalaxySystemsChatDlg(CWnd* pParent = nullptr);	// стандартный конструктор
	virtual ~CGalaxySystemsChatDlg();

// Данные диалогового окна
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_GALAXYSYSTEMSCHAT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// поддержка DDX/DDV


// Реализация
protected:
	CGalaxySystemsChatDlgAutoProxy* m_pAutoProxy;
	HICON m_hIcon;

	BOOL CanExit();

	// Созданные функции схемы сообщений
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClose();
	virtual void OnOK();
	virtual void OnCancel();
	DECLARE_MESSAGE_MAP()
};
