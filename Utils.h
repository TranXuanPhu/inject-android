#pragma once


#ifndef ANDROIDINJECT_UTILS_H
#define ANDROIDINJECT_UTILS_H

#include "../../../__Global/Android/inc/define.h"


UINT get_system_api_level(void);
 //void handle_init();
__unused void handle_libs();
__unused void handle_selinux_init();
__unused void handle_selinux_detect();

#endif //ANDROIDINJECT_UTILS_H

class CUtils
{
public:
	CUtils();
	~CUtils(void);

	// field
public:
	//process_libs
	static const char *libc_path;
	static const char *linker_path;
	static const char *libdl_path;

	//process_selinux
	static const char *selinux_mnt;
	static int enforce;

	//function
public:
	static bool				IsSELinuxEnforce();
	static bool				SetSelinuxState(int value);
	static bool				GetPidByName(pid_t * pid, const char * task_name);
	static void				GetAppStartActivity(char * pkg_name, char * start_activity_name);
	static void				StartApp(char * pkg_name);
	static void*			GetModuleBaseAddr(pid_t pid, const char * ModuleName);
	static void*			GetRemoteFunctionAddr(pid_t pid, const char * ModuleName, void * LocalFuncAddr);


	static LPVOID			Get_mmap_Address(pid_t pid);
	static LPVOID			Get_dlopen_Address(pid_t pid);
	static LPVOID			Get_dlclose_Address(pid_t pid);
	static LPVOID			Get_dlsym_Address(pid_t pid);
	static LPVOID			Get_dlerror_Address(pid_t pid);
};


