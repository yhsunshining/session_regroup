
// session_regroup.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Csession_regroupApp: 
// �йش����ʵ�֣������ session_regroup.cpp
//

class Csession_regroupApp : public CWinApp
{
public:
	Csession_regroupApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern Csession_regroupApp theApp;