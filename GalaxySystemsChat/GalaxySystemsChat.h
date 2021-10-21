
// GalaxySystemsChat.h:
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include pch.h before this file in PCH"
#endif

#include "resource.h"

// CGalaxySystemsChatApp:

class CGalaxySystemsChatApp : public CWinApp
{
public:
	CGalaxySystemsChatApp();

public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	DECLARE_MESSAGE_MAP()
};

extern CGalaxySystemsChatApp theApp;
