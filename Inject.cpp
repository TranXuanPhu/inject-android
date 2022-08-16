#include "Inject.h"

// system lib
#include <asm/ptrace.h>
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

// user lib
#include "Ptrace.h"
#include "Tracer.h"


int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName, char *FlagSELinux) {
	
	
	
	
	printf("-------------------------------------\n");
	CTracer pTracer(pid);

	void* _mapAddress = pTracer.get_map_write();
	printf("_mapAddress [%p]\n", _mapAddress);
	

	printf("-------------------------------------\n");
	
	
	
	
	
	int iRet = -1;
	
}

struct process_inject {
	pid_t pid;
	char lib_path[1024];
	char func_symbols[1024];
	char orig_selinux[1024];
} process_inject = { 0, "", "symbols","Permissive" };


void handle_parameter(int argc, char *argv[]) {
	pid_t pid = 0;
	int index = 0;
	char *pkg_name = NULL;
	char *lib_path = NULL;
	char *func_symbols = NULL;
	bool start_app_flag = false;

	while (index < argc) { 

		if (strcmp("-f", argv[index]) == 0) { 
			start_app_flag = true; 
		}

		if (strcmp("-p", argv[index]) == 0) { 
			if (index + 1 >= argc) {
				printf("[-] Missing parameter -p\n");
				exit(-1);
			}
			index++;
			pid = atoi(argv[index]); // pid
		}

		if (strcmp("-n", argv[index]) == 0) { 
			if (index + 1 >= argc) {
				printf("[-] Missing parameter -n\n");
				exit(-1);
			}
			index++;
			pkg_name = argv[index]; 

			if (start_app_flag) { 
				CUtils::StartApp(pkg_name); 
				sleep(1);
			}
		}

		if (strcmp("-so", argv[index]) == 0) { 
			if (index + 1 >= argc) {
				printf("[-] Missing parameter -so\n");
				exit(-1);
			}
			index++;
			lib_path = argv[index]; 
		}

		if (strcmp("-symbols", argv[index]) == 0) { 
			if (index + 1 >= argc) {
				printf("[-] Missing parameter -func\n");
				exit(-1);
			}
			index++;
			func_symbols = argv[index]; 
		}

		index++;
	}

	

	
	if (pkg_name != NULL) {
		printf("[+] pkg_name is %s\n", pkg_name);
		if (CUtils::GetPidByName(&pid, pkg_name)) {
			printf("[+] get_pid_by_name pid is %d\n", pid);
		}
	}

	
	if (pid == 0) {
		printf("[-] not found target & get_pid_by_name pid faild !\n");
		exit(0);
	}
	else {
		process_inject.pid = pid; 
	}

	
	if (lib_path != NULL) { 
		printf("[+] lib_path is %s\n", lib_path);
		strcpy(process_inject.lib_path, strdup(lib_path)); 
	}

	
	if (func_symbols != NULL) { 
		printf("[+] symbols is %s\n", func_symbols);
		strcpy(process_inject.func_symbols, strdup(func_symbols)); 
	}
}


int init_inject(int argc, char *argv[]) {

	
	handle_parameter(argc, argv);

	printf("[+] handle_parameter is OK\n");

	
	if (CUtils::IsSELinuxEnforce()) { 
		printf("[-] SELinux is Enforcing\n");
		strcpy(process_inject.orig_selinux, strdup("Enforcing"));
		if (CUtils::SetSelinuxState(0)) {
			printf("[+] Selinux has been changed to Permissive\n");
		}
	}
	else { 
		printf("[+] SELinux is Permissive or Disabled\n");
		strcpy(process_inject.orig_selinux, strdup("Permissive"));
	}

	return inject_remote_process(process_inject.pid, process_inject.lib_path, process_inject.func_symbols, process_inject.orig_selinux);
}


int inject_libpath(pid_t pid, char *LibPath) {

}