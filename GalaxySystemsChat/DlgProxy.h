
// DlgProxy.h: файл заголовка
//

#pragma once

class CGalaxySystemsChatDlg;


// Целевой объект команды CGalaxySystemsChatDlgAutoProxy

class CGalaxySystemsChatDlgAutoProxy : public CCmdTarget
{
	DECLARE_DYNCREATE(CGalaxySystemsChatDlgAutoProxy)

	CGalaxySystemsChatDlgAutoProxy();           // защищенный конструктор, используемый при динамическом создании

// Атрибуты
public:
	CGalaxySystemsChatDlg* m_pDialog;

// Операции
public:

// Переопределение
	public:
	virtual void OnFinalRelease();

// Реализация
protected:
	virtual ~CGalaxySystemsChatDlgAutoProxy();

	// Созданные функции схемы сообщений

	DECLARE_MESSAGE_MAP()
	DECLARE_OLECREATE(CGalaxySystemsChatDlgAutoProxy)

	// Автоматически созданные функции диспетчерской карты OLE

	DECLARE_DISPATCH_MAP()
	DECLARE_INTERFACE_MAP()
};

