
// DlgProxy.cpp:
//

#include "pch.h"

#include "GalaxySystemsChat.h"
#include "DlgProxy.h"
#include "GalaxySystemsChatDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CGalaxySystemsChatDlgAutoProxy

IMPLEMENT_DYNCREATE(CGalaxySystemsChatDlgAutoProxy, CCmdTarget)

CGalaxySystemsChatDlgAutoProxy::CGalaxySystemsChatDlgAutoProxy(): m_pDialog(nullptr)
{
	EnableAutomation();

	AfxOleLockApp();

	ASSERT_VALID(AfxGetApp()->m_pMainWnd);
	if (AfxGetApp()->m_pMainWnd)
	{
		ASSERT_KINDOF(CGalaxySystemsChatDlg, AfxGetApp()->m_pMainWnd);
		if (AfxGetApp()->m_pMainWnd->IsKindOf(RUNTIME_CLASS(CGalaxySystemsChatDlg)))
		{
			m_pDialog = reinterpret_cast<CGalaxySystemsChatDlg*>(AfxGetApp()->m_pMainWnd);
			m_pDialog->m_pAutoProxy = this;
		}
	}
}

CGalaxySystemsChatDlgAutoProxy::~CGalaxySystemsChatDlgAutoProxy()
{
	if (m_pDialog != nullptr)
		m_pDialog->m_pAutoProxy = nullptr;
	AfxOleUnlockApp();
}

void CGalaxySystemsChatDlgAutoProxy::OnFinalRelease()
{
	CCmdTarget::OnFinalRelease();
}

BEGIN_MESSAGE_MAP(CGalaxySystemsChatDlgAutoProxy, CCmdTarget)
END_MESSAGE_MAP()

BEGIN_DISPATCH_MAP(CGalaxySystemsChatDlgAutoProxy, CCmdTarget)
END_DISPATCH_MAP()

// {44ccc5db-2872-433f-83ba-65f24fd8da8d}
static const IID IID_IGalaxySystemsChat =
{0x44ccc5db,0x2872,0x433f,{0x83,0xba,0x65,0xf2,0x4f,0xd8,0xda,0x8d}};

BEGIN_INTERFACE_MAP(CGalaxySystemsChatDlgAutoProxy, CCmdTarget)
	INTERFACE_PART(CGalaxySystemsChatDlgAutoProxy, IID_IGalaxySystemsChat, Dispatch)
END_INTERFACE_MAP()

// {3e56574b-57e1-40a5-bc5b-edd84a78302d}
IMPLEMENT_OLECREATE2(CGalaxySystemsChatDlgAutoProxy, "GalaxySystemsChat.Application", 0x3e56574b,0x57e1,0x40a5,0xbc,0x5b,0xed,0xd8,0x4a,0x78,0x30,0x2d)


// CGalaxySystemsChatDlgAutoProxy
