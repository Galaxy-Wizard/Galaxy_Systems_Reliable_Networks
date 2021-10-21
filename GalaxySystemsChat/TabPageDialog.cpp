// TabPageDialog.cpp : implementation file
//

#include "pch.h"
#include "TabPageDialog.h"
#include "afxdialogex.h"
#include "resource.h"


// TabPageDialog dialog

IMPLEMENT_DYNAMIC(TabPageDialog, CDialogEx)

TabPageDialog::TabPageDialog(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_TAB_PAGE, pParent)
{

}

TabPageDialog::~TabPageDialog()
{
}

void TabPageDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, PrivateChat);
	DDX_Control(pDX, IDC_EDIT2, PrivateAnswer);
}


BEGIN_MESSAGE_MAP(TabPageDialog, CDialogEx)
END_MESSAGE_MAP()


// TabPageDialog message handlers
