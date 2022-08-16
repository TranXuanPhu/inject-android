#include "Tracer.h"



CTracer::CTracer(int	pid)
{
	m_pid = pid;
	m_bAttached = FALSE;
	m_pMemWrite = NULL;
	ptrace_attach();

	m_pMemWrite = get_map_write();

}


CTracer::~CTracer()
{
	ptrace_detach();
}

int CTracer::ptrace_attach()
{
	if (m_bAttached) return 0;
	int status = 0;
	if (ptrace(PTRACE_ATTACH, m_pid, NULL, NULL) < 0) {
		printf("[-] ptrace attach process error, pid:%d, err:%s\n", m_pid, strerror(errno));
		return -1;
	}

	printf("[+] attach porcess success, pid:%d\n", m_pid);
	waitpid(m_pid, &status, WUNTRACED);

	m_bAttached = TRUE;
	return 0;
}

int CTracer::ptrace_continue()
{
	if (ptrace(PTRACE_CONT, m_pid, NULL, NULL) < 0) {
		printf("[-] ptrace continue process error, pid:%d, err:%ss\n", m_pid, strerror(errno));
		return -1;
	}

	printf("[+] ptrace continue process success, pid:%d\n", m_pid);
	return 0;
}

int CTracer::ptrace_detach()
{
	if (m_bAttached) return 0;
	if (ptrace(PTRACE_DETACH, m_pid, NULL, 0) < 0) {
		printf("[-] detach process error, pid:%d, err:%s\n", m_pid, strerror(errno));
		return -1;
	}

	printf("[+] detach process success, pid:%d\n", m_pid);
	m_bAttached = FALSE;
	return 0;
}

int CTracer::ptrace_getregs(pt_regs * regs)
{
	if (!m_bAttached) return -1;

#if defined(__aarch64__)
	int regset = NT_PRSTATUS;
	struct iovec ioVec;

	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);
	if (ptrace(PTRACE_GETREGSET, m_pid, (void *)regset, &ioVec) < 0) {
		printf("[-] ptrace_getregs: Can not get register values, io %llx, %d\n", ioVec.iov_base, ioVec.iov_len);
		return -1;
	}

	return 0;
#else
	if (ptrace(PTRACE_GETREGS, m_pid, NULL, regs) < 0) {
		printf("[-] Get Regs error, pid:%d, err:%s\n", m_pid, strerror(errno));
		return -1;
	}
#endif
	return 0;
}

int CTracer::ptrace_setregs(pt_regs * regs)
{
	if (!m_bAttached) return -1;

#if defined(__aarch64__)
	int regset = NT_PRSTATUS;
	struct iovec ioVec;

	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);
	if (ptrace(PTRACE_SETREGSET, m_pid, (void *)regset, &ioVec) < 0) {
		perror("[-] ptrace_setregs: Can not get register values");
		return -1;
	}

	return 0;
#else
	if (ptrace(PTRACE_SETREGS, m_pid, NULL, regs) < 0) {
		printf("[-] Set Regs error, pid:%d, err:%s\n", m_pid, strerror(errno));
		return -1;
	}
#endif
	return 0;
}

long CTracer::ptrace_getret(pt_regs * regs)
{
#if defined(__i386__) || defined(__x86_64__) 
	return regs->eax;
#elif defined(__arm__) || defined(__aarch64__)
	return regs->ARM_r0;
#else
	printf("Not supported Environment %s\n", __FUNCTION__);
#endif
}

long CTracer::ptrace_getpc(pt_regs * regs)
{
#if defined(__i386__) || defined(__x86_64__)
	return regs->eip;
#elif defined(__arm__) || defined(__aarch64__)
	return regs->ARM_pc;
#else
	printf("Not supported Environment %s\n", __FUNCTION__);
#endif
}

int CTracer::ptrace_readdata(uint8_t * pSrcBuf, uint8_t * pDestBuf, size_t size)
{
	if (!m_bAttached) return -1;

	long nReadCount = 0;
	long nRemainCount = 0;
	uint8_t *pCurSrcBuf = pSrcBuf;
	uint8_t *pCurDestBuf = pDestBuf;
	long lTmpBuf = 0;
	long i = 0;

	nReadCount = size / sizeof(long);
	nRemainCount = size % sizeof(long);

	for (i = 0; i < nReadCount; i++) {
		lTmpBuf = ptrace(PTRACE_PEEKTEXT, m_pid, pCurSrcBuf, 0);
		memcpy(pCurDestBuf, (char *)(&lTmpBuf), sizeof(long));
		pCurSrcBuf += sizeof(long);
		pCurDestBuf += sizeof(long);
	}

	if (nRemainCount > 0) {
		lTmpBuf = ptrace(PTRACE_PEEKTEXT, m_pid, pCurSrcBuf, 0);
		memcpy(pCurDestBuf, (char *)(&lTmpBuf), nRemainCount);
	}

	return 0;
}

int CTracer::ptrace_writedata(uint8_t * pWriteAddr, uint8_t * pWriteData, size_t size)
{
	if (!m_bAttached) return -1;

	long nWriteCount = 0;
	long nRemainCount = 0;
	uint8_t *pCurSrcBuf = pWriteData;
	uint8_t *pCurDestBuf = pWriteAddr;
	long lTmpBuf = 0;
	long i = 0;

	nWriteCount = size / sizeof(long);
	nRemainCount = size % sizeof(long);

	
	for (i = 0; i < nWriteCount; i++) {
		memcpy((void *)(&lTmpBuf), pCurSrcBuf, sizeof(long));
		if (ptrace(PTRACE_POKETEXT, m_pid, (void *)pCurDestBuf, (void *)lTmpBuf) < 0) {
			printf("[-] Write Remote Memory error, MemoryAddr:0x%lx, err:%s\n", (uintptr_t)pCurDestBuf, strerror(errno));
			return -1;
		}
		pCurSrcBuf += sizeof(long);
		pCurDestBuf += sizeof(long);
	}
	
	if (nRemainCount > 0) {
		lTmpBuf = ptrace(PTRACE_PEEKTEXT, m_pid, pCurDestBuf, NULL); 
		memcpy((void *)(&lTmpBuf), pCurSrcBuf, nRemainCount);
		if (ptrace(PTRACE_POKETEXT, m_pid, pCurDestBuf, lTmpBuf) < 0) {
			printf("[-] Write Remote Memory error, MemoryAddr:0x%lx, err:%s\n", (uintptr_t)pCurDestBuf, strerror(errno));
			return -1;
		}
	}
	return 0;
}

int CTracer::ptrace_call(uintptr_t ExecuteAddr, long * parameters, long num_params, pt_regs * regs)
{
	if (!m_bAttached) return -1;

#if defined(__i386__) 
	
	regs->esp -= (num_params) * sizeof(long); 
	if (0 != ptrace_writedata((uint8_t *)regs->esp, (uint8_t *)parameters, (num_params) * sizeof(long))) {
		return -1;
	}

	long tmp_addr = 0x0;
	regs->esp -= sizeof(long);
	if (0 != ptrace_writedata((uint8_t *)regs->esp, (uint8_t *)&tmp_addr, sizeof(tmp_addr))) {
		return -1;
	}

	
	regs->eip = ExecuteAddr;

	
	if (-1 == ptrace_setregs(regs) || -1 == ptrace_continue()) {
		printf("[-] ptrace set regs or continue error, pid:%d\n", m_pid);
		return -1;
	}

	int stat = 0;
	
	waitpid(m_pid, &stat, WUNTRACED);

	
	printf("[+] ptrace call ret status is %d\n", stat);
	while (stat != 0xb7f) {
		if (ptrace_continue() == -1) {
			printf("[-] ptrace call error");
			return -1;
		}
		waitpid(m_pid, &stat, WUNTRACED);
	}

	
	if (ptrace_getregs(regs) == -1) {
		printf("[-] After call getregs error");
		return -1;
	}

#elif defined(__x86_64__) // ？？
	int num_param_registers = 6;
	
	if (num_params > 0)
		regs->rdi = parameters[0];
	if (num_params > 1)
		regs->rsi = parameters[1];
	if (num_params > 2)
		regs->rdx = parameters[2];
	if (num_params > 3)
		regs->rcx = parameters[3];
	if (num_params > 4)
		regs->r8 = parameters[4];
	if (num_params > 5)
		regs->r9 = parameters[5];

	if (num_param_registers < num_params) {
		regs->esp -= (num_params - num_param_registers) * sizeof(long); 
		if (0 != ptrace_writedata((uint8_t *)regs->esp, (uint8_t *)&parameters[num_param_registers], (num_params - num_param_registers) * sizeof(long))) {
			return -1;
		}
	}

	long tmp_addr = 0x0;
	regs->esp -= sizeof(long);
	if (0 != ptrace_writedata((uint8_t *)regs->esp, (uint8_t *)&tmp_addr, sizeof(tmp_addr))) {
		return -1;
	}

	
	regs->eip = ExecuteAddr;

	
	if (-1 == ptrace_setregs(regs) || -1 == ptrace_continue()) {
		printf("[-] ptrace set regs or continue error, pid:%d", m_pid);
		return -1;
	}

	int stat = 0;
	
	waitpid(m_pid, &stat, WUNTRACED);

	
	printf("ptrace call ret status is %lX\n", stat);
	while (stat != 0xb7f) {
		if (ptrace_continue() == -1) {
			printf("[-] ptrace call error");
			return -1;
		}
		waitpid(m_pid, &stat, WUNTRACED);
	}

#elif defined(__arm__) || defined(__aarch64__) 
#if defined(__arm__) 
	int num_param_registers = 4;
#elif defined(__aarch64__) 
	int num_param_registers = 8;
#endif
	int i = 0;
	
	for (i = 0; i < num_params && i < num_param_registers; i++) {
		regs->uregs[i] = parameters[i];
	}

	if (i < num_params) {
		regs->ARM_sp -= (num_params - i) * sizeof(long); 
		if (ptrace_writedata( (uint8_t *)(regs->ARM_sp), (uint8_t *)&parameters[i], (num_params - i) * sizeof(long)) == -1)
			return -1;
	}

	regs->ARM_pc = ExecuteAddr; 
	if (regs->ARM_pc & 1) {
		/* thumb */
		regs->ARM_pc &= (~1u);
		regs->ARM_cpsr |= CPSR_T_MASK;
	}
	else {
		/* arm */
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}

	regs->ARM_lr = 0;

	long lr_val = 0;
	char sdk_ver[32];
	memset(sdk_ver, 0, sizeof(sdk_ver));
	__system_property_get("ro.build.version.sdk", sdk_ver);
	//    printf("ro.build.version.sdk: %s", sdk_ver);
	if (atoi(sdk_ver) <= 23) {
		lr_val = 0;
	}
	else { // Android 7.0
		static long start_ptr = 0;
		if (start_ptr == 0) {
			start_ptr = (long)get_module_base_addr(pid, process_libs.libc_path);
		}
		lr_val = start_ptr;
	}
	regs->ARM_lr = lr_val;

	if (ptrace_setregs( regs) == -1 || ptrace_continue() == -1) {
		printf("[-] ptrace set regs or continue error, pid:%d\n", m_pid);
		return -1;
	}

	int stat = 0;
	
	waitpid(m_pid, &stat, WUNTRACED);

	
	printf("[+] ptrace call ret status is %d\n", stat);
	while ((stat & 0xFF) != 0x7f) {
		if (ptrace_continue() == -1) {
			printf("[-] ptrace call error\n");
			return -1;
		}
		waitpid(m_pid, &stat, WUNTRACED);
	}

	
	if (ptrace_getregs( regs) == -1) {
		printf("[-] After call getregs error\n");
		return -1;
	}

#else 
	printf("[-] Not supported Environment %s\n", __FUNCTION__);
#endif
	return 0;
}

void * CTracer::get_map_write()
{
	if (!m_bAttached) return nullptr;

	printf("CTracer::get_map_write() \n");

	void* _mapWriteAddress = NULL;
	long parameters[6];
	
	if (ptrace_attach() != 0) {
		printf("CTracer::get_map_write()2222 \n");
		return NULL;
	}
	printf("CTracer::get_map_write() 11111\n");
	do {
		
		struct pt_regs CurrentRegs, OriginalRegs;
		if (ptrace_getregs(&CurrentRegs) != 0) {
			break;
		}
		
		memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs));

		void *mmap_addr = CUtils::Get_mmap_Address(m_pid);
		printf("[+] mmap RemoteFuncAddr:0x%lx\n", (uintptr_t)mmap_addr);

		parameters[0] = 0; 
		parameters[1] = 0x3000;
		parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC; 
		parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; 
		parameters[4] = 0;

		if (ptrace_call((uintptr_t)mmap_addr, parameters, 6, &CurrentRegs) == -1) {
			printf("[-] Call Remote mmap Func Failed, err:%s\n", strerror(errno));
			break;
		}

		
		printf("[+] ptrace_call mmap success, return value=%lX, pc=%lX\n", ptrace_getret(&CurrentRegs), ptrace_getpc(&CurrentRegs));

		
		_mapWriteAddress = (void *)ptrace_getret(&CurrentRegs);
		printf("[+] Remote Process Map Memory Addr:0x%lx\n", (uintptr_t)_mapWriteAddress);


		if (ptrace_setregs(&OriginalRegs) == -1) {
			printf("[-] Recover reges failed\n");
			break;
		}

		printf("[+] Recover Regs Success\n");

		ptrace_getregs(&CurrentRegs);
		if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0) {
			printf("[-] Set Regs Error\n");
		}

	} while (false);

	
	ptrace_detach();

	return _mapWriteAddress;
}
