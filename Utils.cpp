
// system lib
#include <asm/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <elf.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/system_properties.h>

#include "Utils.h"

const char* CUtils::libc_path	= "";
const char* CUtils::linker_path = "";
const char* CUtils::libdl_path	= "";

const char* CUtils::selinux_mnt = NULL;
int			CUtils::enforce = -1;

UINT get_system_api_level(void)
{
	char sdk_version[PROP_VALUE_MAX];
	sdk_version[0] = '\0';
	__system_property_get("ro.build.version.sdk", sdk_version);
	return atoi(sdk_version);
}


// __attribute__((constructor))void handle_init() {
//	//handle_libs();
//	//handle_selinux_init();
//	//handle_selinux_detect();
//}
__unused __attribute__((constructor(101))) void handle_libs() { 
	
#if defined(__aarch64__) || defined(__x86_64__)
	
	if (atoi(sdk_ver) >= __ANDROID_API_Q__) {
		CUtils::libc_path = "/apex/com.android.runtime/lib64/bionic/libc.so";
		CUtils::linker_path = "/apex/com.android.runtime/bin/linker64";
		CUtils::libdl_path = "/apex/com.android.runtime/lib64/bionic/libdl.so";
	}
	else {
		CUtils::libc_path = "/system/lib64/libc.so";
		CUtils::linker_path = "/system/bin/linker64";
		CUtils::libdl_path = "/system/lib64/libdl.so";
	}
#else
	
	if (get_system_api_level() >= __ANDROID_API_Q__) {
		CUtils::libc_path = "/apex/com.android.runtime/lib/bionic/libc.so";
		CUtils::linker_path = "/apex/com.android.runtime/bin/linker";
		CUtils::libdl_path = "/apex/com.android.runtime/lib/bionic/libdl.so";
	}
	else {
		CUtils::libc_path = "/system/lib/libc.so";
		CUtils::linker_path = "/system/bin/linker";
		CUtils::libdl_path = "/system/lib/libdl.so";
	}
#endif
	printf("[+] libc_path is %s\n", CUtils::libc_path);
	printf("[+] linker_path is %s\n", CUtils::linker_path);
	printf("[+] libdl_path is %s\n", CUtils::libdl_path);
	printf("[+] system libs is OK\n");
}



__unused __attribute__((constructor(102))) void handle_selinux_init() { 
	// code from AOSP
	char buf[BUFSIZ], *p;
	FILE *fp = NULL;
	struct statfs sfbuf;
	int rc;
	char *bufp;
	int exists = 0;

	if (CUtils::selinux_mnt) { 
		return;
	}

	/* We check to see if the preferred mount point for selinux file
	 * system has a selinuxfs. */
	do {
		rc = statfs("/sys/fs/selinux", &sfbuf);
	} while (rc < 0 && errno == EINTR);
	if (rc == 0) {
		if ((uint32_t)sfbuf.f_type == (uint32_t)SELINUX_MAGIC) {
			CUtils::selinux_mnt = strdup("/sys/fs/selinux"); 
			return;
		}
	}

	/* Drop back to detecting it the long way. */
	fp = fopen("/proc/filesystems", "r");
	if (!fp) {
		return;
	}

	while ((bufp = fgets(buf, sizeof buf - 1, fp)) != NULL) {
		if (strstr(buf, "selinuxfs")) {
			exists = 1;
			break;
		}
	}

	if (!exists) {
		goto out;
	}

	fclose(fp);

	/* At this point, the usual spot doesn't have an selinuxfs so
	 * we look around for it */
	fp = fopen("/proc/mounts", "r");
	if (!fp) {
		goto out;
	}

	while ((bufp = fgets(buf, sizeof buf - 1, fp)) != NULL) {
		char *tmp;
		p = strchr(buf, ' ');
		if (!p) {
			goto out;
		}
		p++;
		tmp = strchr(p, ' ');
		if (!tmp) {
			goto out;
		}
		if (!strncmp(tmp + 1, "selinuxfs ", 10)) {
			*tmp = '\0';
			break;
		}
	}

	/* If we found something, dup it */
	if (bufp) {
		CUtils::selinux_mnt = strdup(p);
	}

out:
	if (fp) {
		fclose(fp);
	}

	return;
}


__unused __attribute__((constructor(103))) void handle_selinux_detect() {
	// code from AOSP
	int fd, ret;
	char path[PATH_MAX];
	char buf[20];

	if (!CUtils::selinux_mnt) { 
		errno = ENOENT;
		printf("[-] selinux_mnt is NULL\n");
		return;
	}

	snprintf(path, sizeof path, "%s/enforce", CUtils::selinux_mnt);
	fd = open(path, O_RDONLY);
	if (fd < 0) { 
		printf("[-] Failed to open enforce\n");
		return;
	}

	memset(buf, 0, sizeof buf);
	ret = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (ret < 0) { 
		printf("[-] SELinux ret error\n");
		return;
	}

	
	if (sscanf(buf, "%d", (int*)&CUtils::enforce) != 1) { // 如果失败 则终止
		printf("[-] sscanf error\n");
		return;
	}
	printf("[+] handle_selinux_init is OK\n");
	return;
}

CUtils::CUtils()
{
	
}

CUtils::~CUtils(void)
{
}

bool CUtils::IsSELinuxEnforce()
{
	return CUtils::enforce == 1;
}

bool CUtils::SetSelinuxState(int value)
{
	bool succ = true;
	int fd;
	char path[PATH_MAX];
	char buf[20];

	if (!selinux_mnt) {
		errno = ENOENT;
		return -1;
	}

	snprintf(path, sizeof path, "%s/enforce", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	snprintf(buf, sizeof buf, "%d", (int)value);
	int ret = write(fd, buf, strlen(buf));
	close(fd);
	if (ret < 0)
		succ = false;
	return succ;
}

bool CUtils::GetPidByName(pid_t * pid,const char * task_name)
{
	DIR *dir;
	struct dirent *ptr;
	FILE *fp;
	char filepath[50];
	char cur_task_name[50];
	char buf[1024];

	dir = opendir("/proc");
	if (NULL != dir) {
		while ((ptr = readdir(dir)) != NULL) { 
			if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
				continue;
			if (DT_DIR != ptr->d_type)
				continue;

			sprintf(filepath, "/proc/%s/cmdline", ptr->d_name); 
			fp = fopen(filepath, "r");
			if (NULL != fp) {
				if (fgets(buf, 1024 - 1, fp) == NULL) {
					fclose(fp);
					continue;
				}
				sscanf(buf, "%s", cur_task_name);
				if (strstr(task_name, cur_task_name)) {
					*pid = atoi(ptr->d_name);
					return true;
				}
				fclose(fp);
			}
		}
		closedir(dir);
	}

	return false;
}

void CUtils::GetAppStartActivity(char * pkg_name, char * start_activity_name)
{
	char cmdstring[1024] = "dumpsys package ";
	char cmd_string[1024] = { 0 };
	char temp_file[] = "tmp_XXXXXX";

	strcat(cmdstring, pkg_name);
	int fd;

	if ((fd = mkstemp(temp_file)) == -1) {
		printf("[-] create tmp file failed.\n");
	}

	sprintf(cmd_string, "%s > %s", cmdstring, temp_file);
	system(cmd_string);

	FILE *fp = fdopen(fd, "r");
	if (fp == NULL) {
		printf("[-] can not load file!");
		return;
	}
	char line[1024];
	while (!feof(fp)) {
		fgets(line, 1024, fp);
		if (strstr(line, "android.intent.action.MAIN")) {
			fgets(line, 1024, fp);
			char *p;
			int index = 1;
			p = strtok(line, " ");
			while (p) {
				if (index == 2) {
					strcpy(start_activity_name, p);
				}
				index++;
				p = strtok(NULL, " ");
			}
			break;
		}
	}
	fclose(fp);
	unlink(temp_file);
	return;
}

void CUtils::StartApp(char * pkg_name)
{
	char start_activity_name[1024] = { 0 };
	CUtils::GetAppStartActivity(pkg_name, start_activity_name);
	printf("[+] app_start_activity is %s\n", start_activity_name);
	char start_cmd[1024] = "am start ";
	strcat(start_cmd, start_activity_name);
	printf("[+] %s\n", start_cmd);
	system(start_cmd);
}

void * CUtils::GetModuleBaseAddr(pid_t pid, const char * ModuleName)
{
	FILE *fp = NULL;
	long ModuleBaseAddr = 0;
	char szFileName[50] = { 0 };
	char szMapFileLine[1024] = { 0 };

	if (pid < 0) {
		snprintf(szFileName, sizeof(szFileName), "/proc/self/maps");
	}
	else {
		snprintf(szFileName, sizeof(szFileName), "/proc/%d/maps", pid);
	}

	fp = fopen(szFileName, "r");

	if (fp != NULL) {
		while (fgets(szMapFileLine, sizeof(szMapFileLine), fp)) {
			if (strstr(szMapFileLine, ModuleName)) {
				char *Addr = strtok(szMapFileLine, "-");
				ModuleBaseAddr = strtoul(Addr, NULL, 16);

				if (ModuleBaseAddr == 0x8000)
					ModuleBaseAddr = 0;

				break;
			}
		}

		fclose(fp);
	}

	return (void *)ModuleBaseAddr;
}

void * CUtils::GetRemoteFunctionAddr(pid_t pid, const char * ModuleName, void * LocalFuncAddr)
{
	void *LocalModuleAddr, *RemoteModuleAddr, *RemoteFuncAddr;
	LocalModuleAddr = GetModuleBaseAddr(-1, ModuleName);
	RemoteModuleAddr = GetModuleBaseAddr(pid, ModuleName);
	RemoteFuncAddr = (void *)((uintptr_t)LocalFuncAddr - (uintptr_t)LocalModuleAddr + (uintptr_t)RemoteModuleAddr);

	return RemoteFuncAddr;
}

LPVOID CUtils::Get_mmap_Address(pid_t pid)
{
	return GetRemoteFunctionAddr(pid, libc_path, (void *)mmap);
}


LPVOID CUtils::Get_dlopen_Address(pid_t pid)
{
	void *dlopen_addr;
	if (get_system_api_level() <= 23) {
		dlopen_addr = GetRemoteFunctionAddr(pid, linker_path, (void *)dlopen);
	}
	else {
		dlopen_addr = GetRemoteFunctionAddr(pid, libdl_path, (void *)dlopen);
	}
	//printf("[+] dlopen RemoteFuncAddr:0x%lx\n", (uintptr_t)dlopen_addr);
	return dlopen_addr;
}

LPVOID CUtils::Get_dlclose_Address(pid_t pid)
{
	void *dlclose_addr;
	if (get_system_api_level() <= 23) {
		dlclose_addr = GetRemoteFunctionAddr(pid,linker_path, (void *)dlclose);
	}
	else {
		dlclose_addr = GetRemoteFunctionAddr(pid, libdl_path, (void *)dlclose);
	}
	//printf("[+] dlclose RemoteFuncAddr:0x%lx\n", (uintptr_t)dlclose_addr);
	return dlclose_addr;
}

LPVOID CUtils::Get_dlsym_Address(pid_t pid)
{
	void *dlsym_addr;
	if (get_system_api_level() <= 23) {
		dlsym_addr = GetRemoteFunctionAddr(pid,linker_path, (void *)dlsym);
	}
	else {
		dlsym_addr = GetRemoteFunctionAddr(pid, libdl_path, (void *)dlsym);
	}
	//printf("[+] dlsym RemoteFuncAddr:0x%lx\n", (uintptr_t)dlsym_addr);
	return dlsym_addr;
}
LPVOID CUtils::Get_dlerror_Address(pid_t pid)
{
	void *dlerror_addr;
	if (get_system_api_level() <= 23) {
		dlerror_addr = GetRemoteFunctionAddr(pid, linker_path, (void *)dlerror);
	}
	else {
		dlerror_addr = GetRemoteFunctionAddr(pid, libdl_path, (void *)dlerror);
	}
	//printf("[+] dlerror RemoteFuncAddr:0x%lx\n", (uintptr_t)dlerror_addr);
	return dlerror_addr;
}
