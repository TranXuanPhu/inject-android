#include "ProcessInject.h"



CProcessInject::CProcessInject(int pid, int type)
{
	m_pid = pid;
	m_type = type;
}


CProcessInject::~CProcessInject()
{
}

void * CProcessInject::LoadLibrary(LPCSTR LibPath)
{
	int iRet = -1;
	long parameters[6];



	return nullptr;
}

void * CProcessInject::GetProcAddress(void * handle, LPCSTR nameProc)
{
	return nullptr;
}

int CProcessInject::JNI_OnLoad(void * pOnLoad, void * vm, void * reserved)
{
	return 0;
}


