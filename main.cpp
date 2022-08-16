#include "main.h"
#include "Inject.h"
#include <linux/elf.h>
int main(int argc, char* argv[]) {

	if (init_inject(argc, argv) == 0) {
		printf("[+] Finish Inject\n");
	}
	else {
		printf("[-] Inject Erro\n");
	}
	return 1;
}