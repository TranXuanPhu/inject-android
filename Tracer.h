#pragma once

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <elf.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/user.h>

#include "Utils.h"

#if defined(__aarch64__) 
#define pt_regs user_pt_regs
#define uregs regs
#define ARM_pc pc
#define ARM_sp sp
#define ARM_cpsr pstate
#define ARM_lr regs[30]
#define ARM_r0 regs[0]
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#elif defined(__x86_64__) 
#define pt_regs user_regs_struct
#define eax rax
#define esp rsp
#define eip rip
#elif defined(__i386__) 
#define pt_regs user_regs_struct
#endif


#define CPSR_T_MASK (1u << 5)




class CTracer
{
public:
	CTracer(int	pid);
	~CTracer();

	int ptrace_attach();
	int ptrace_continue();
	int ptrace_detach();
	int ptrace_getregs( struct pt_regs *regs);
	int ptrace_setregs( struct pt_regs *regs);
	long ptrace_getret(struct pt_regs *regs);
	long ptrace_getpc(struct pt_regs *regs);
	int ptrace_readdata( uint8_t *pSrcBuf, uint8_t *pDestBuf, size_t size);
	int ptrace_writedata( uint8_t *pWriteAddr, uint8_t *pWriteData, size_t size);
	int ptrace_call(uintptr_t ExecuteAddr, long *parameters, long num_params, struct pt_regs *regs);

	void* get_map_write();


protected:

	int				m_pid;
	BOOL			m_bAttached;
	LPVOID			m_pMemWrite;
};

