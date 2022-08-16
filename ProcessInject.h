#pragma once
#include "../../../__Global/Android/inc/define.h"
#include "Ptrace.h"
class CProcessInject
{
public:
	CProcessInject(int pid, int type);//0:unknow, 1:x86, 2:arm 
	~CProcessInject();

	void*			LoadLibrary(LPCSTR LibPath);
	void*			GetProcAddress(void* handle, LPCSTR nameProc);//void *dlsym(void *handle, const char *symbol);
	int				JNI_OnLoad(void* pOnLoad, void* vm, void* reserved = NULL);
protected:
	int	m_pid;
	int m_type;
};

