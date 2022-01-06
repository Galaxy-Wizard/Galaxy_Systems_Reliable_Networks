#pragma once

#include <afxwin.h>

#include "resource.h"

class CAboutDialog :
    public CDialogEx
{
public:
	CAboutDialog(CWnd* pParent = nullptr)
		: CDialogEx(IDD_ABOUTBOX, pParent)
	{

	}
	virtual ~CAboutDialog() 
	{}
};

