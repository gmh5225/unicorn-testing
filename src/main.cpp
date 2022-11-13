#include <iostream>
#include <string.h>
#include <unicorn/unicorn.h>

// memory address where emulation starts
#define ADDRESS 0x401000

// code to be emulated
unsigned char X86_CODE32[] = {
    0x8F, 0x05, 0x2D, 0xF0, 0x41, 0x00, 0x50, 0xB8, 0xCC, 0xCC, 0xCC,
    0xCC, 0x8D, 0x80, 0x9C, 0x8F, 0xDB, 0x74, 0x87, 0x05, 0x1B, 0xF0,
    0x41, 0x00, 0x58, 0x90, 0x90, 0xBB, 0xBB, 0xBB, 0xBB, 0x00, 0x50,
    0x66, 0xB8, 0xEB, 0xE9, 0x66, 0x87, 0x05, 0x1B, 0xF0, 0x41, 0x00,
    0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0x87, 0x04, 0x24, 0xC3};
unsigned char X86_CODE32_RET[] = {0x90, 0xc3};
// callback for tracing basic blocks
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data) {
  printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
         address, size);
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data) {
  int eflags;
  printf(">>> Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n",
         address, size);

  uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
  printf(">>> --- EFLAGS is 0x%x\n", eflags);

  int esp;
  uc_reg_read(uc, UC_X86_REG_ESP, &esp);
  printf(">>> --- esp is 0x%x\n", esp);

  // read esp
  int espdata = 0;
  uc_mem_read(uc, esp, &espdata, sizeof(espdata));
  printf(">>> --- espdata is 0x%x\n", espdata);

  // Uncomment below code to stop the emulation using uc_emu_stop()
  if (address == /*0x41f034*/ 0x0040104F)
    uc_emu_stop(uc);
}

#define PAGE_4KB 0x1000

void invalid_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
                 int64_t value, void *user_data) {
  switch (type) {
  case UC_MEM_READ_UNMAPPED: {
    uc_mem_map(uc, address & ~0xFFFull, PAGE_4KB, UC_PROT_ALL);
    std::printf(">>> reading invalid memory at address = %p, size = 0x%x\n",
                address, size);
    break;
  }
  case UC_MEM_WRITE_UNMAPPED: {
    uc_mem_map(uc, address & ~0xFFFull, PAGE_4KB, UC_PROT_ALL);
    std::printf(
        ">>> writing invalid memory at address = %p, size = 0x%x, val = "
        "0x%x\n",
        address, size, value);
    break;
  }
  case UC_MEM_FETCH_UNMAPPED: {
    std::printf(">>> fetching invalid instructions at address = %p\n", address);
    break;
  }
  default:
    break;
  }
}

static void hook_mem64(uc_engine *uc, uc_mem_type type, uint64_t address,
                       int size, int64_t value, void *user_data) {
  switch (type) {
  default:
    break;
  case UC_MEM_READ: {
    //// hack espdata
    //// 0x19ff28
    // if (0x19ff28 == address) {
    //   int data = 0x0040105E;
    //   int err = uc_mem_write(uc, 0x19ff28, &data, 4);
    //   if (err) {
    //     printf("hook_mem64:uc_mem_write esp failed!\n");
    //   }
    // }
    printf(">>> Memory is being READ at 0x%" PRIx64
           ", data size = %u, data value = 0x%" PRIx64 "\n",
           address, size, value);
  }

  break;
  case UC_MEM_WRITE:
    printf(">>> Memory is being WRITE at 0x%" PRIx64
           ", data size = %u, data value = 0x%" PRIx64 "\n",
           address, size, value);
    break;
  }
}

static void test_i386_map_ptr(void) {
  uc_engine *uc;
  uc_err err;
  uint32_t tmp;
  uc_hook trace1, trace2, invalid_mem_hook, hook_mem_trace_read,
      hook_mem_trace_write;
  void *mem;

  printf("===================================\n");
  printf("Emulate i386 code - use uc_mem_map_ptr()\n");

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
  if (err) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return;
  }

  uc_mem_map(uc, ADDRESS, 20 * 1024 * 1024, UC_PROT_ALL);
  if ((err = uc_mem_write(uc, 0x41F000, X86_CODE32, sizeof(X86_CODE32)))) {
    std::printf("> failed to write memory... reason = %d\n", err);
    return;
  }

  uint64_t r_esp = 0x0019FF28;
  uint64_t r_esp_base = r_esp & ~0xFFFull;

  // map rsp
  uc_mem_map(uc, r_esp_base, 2 * 1024 * 1024, UC_PROT_ALL);

  // map text
  // uc_mem_map(uc, 0x00401000, 10 * 1024 * 1024, UC_PROT_ALL);
  uc_mem_write(uc, 0x0040104E, X86_CODE32_RET, sizeof(X86_CODE32_RET));

  int r_ecx = 0;          // ECX register
  int r_edx = 0x0331FD10; // EDX register
  int r_eax = 0x0041CE48;
  int r_ebx = 0x00328000;
  int r_ebp = 0x0019FF2C;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
  uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
  uc_reg_write(uc, UC_X86_REG_EBX, &r_ebx);
  uc_reg_write(uc, UC_X86_REG_EBP, &r_ebp);
  uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);

  int data = 0x0040104E;
  err = uc_mem_write(uc, r_esp, &data, 4);
  if (err) {
    printf("uc_mem_write esp failed!\n");
  }

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

  if ((err =
           uc_hook_add(uc, &invalid_mem_hook,
                       UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                           UC_HOOK_MEM_FETCH_UNMAPPED,
                       (void *)&invalid_mem, NULL, 1, 0))) {
    std::printf("> uc_hook_add error, reason = %d\n", err);
    return;
  }

  // tracing all memory READ/WRITE access (with @begin > @end)
  uc_hook_add(uc, &hook_mem_trace_read, UC_HOOK_MEM_READ, hook_mem64, NULL, 1,
              0);
  uc_hook_add(uc, &hook_mem_trace_write, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1,
              0);

  // emulate machine code in infinite time
  err = uc_emu_start(uc, 0x41F000, 2 * 1024 * 1024, 0, 0);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n", err,
           uc_strerror(err));
  }

  // now print out some registers
  printf(">>> Emulation done. Below is the CPU context\n");

  uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
  int r_return_esp = 0;
  uc_reg_read(uc, UC_X86_REG_ESP, &r_return_esp);
  int r_return_ebp = 0;
  uc_reg_read(uc, UC_X86_REG_EBP, &r_return_ebp);
  printf(">>> ECX = 0x%x\n", r_ecx);
  printf(">>> EDX = 0x%x\n", r_edx);
  printf(">>> ESP = 0x%x\n", r_return_esp);
  printf(">>> EBP = 0x%x\n", r_return_ebp);

  // read from memory
  if (!uc_mem_read(uc, ADDRESS, &tmp, sizeof(tmp)))
    printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS, tmp);
  else
    printf(">>> Failed to read 4 bytes from [0x%x]\n", ADDRESS);

  // read esp
  if (!uc_mem_read(uc, r_esp, &tmp, sizeof(tmp)))
    printf(">>> Read esp from [0x%x] = 0x%x\n", r_esp, tmp);
  else
    printf(">>> Failed to read esp from [0x%x]\n", r_esp);

  uc_close(uc);
}

static void test_i386_1(void) {
  uc_engine *uc;
  uc_err err;
  uint32_t tmp;
  uc_hook trace1, trace2, invalid_mem_hook, hook_mem_trace_read,
      hook_mem_trace_write;
  void *mem;

  printf("===================================\n");
  printf("test_i386_1\n");

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
  if (err) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return;
  }

  /*
0040504A  50                                    push eax
0040504B  8B 04 24                              mov eax, dword ptr ss:[esp]
0040504E  50                                    push eax
0040504F  8B 04 24                              mov eax, dword ptr ss:[esp]
00405052  89 84 24 04 00 00 00                  mov dword ptr ss:[esp+0x4], eax
00405059  53                                    push ebx
0040505A  8B 9C 24 04 00 00 00                  mov ebx, dword ptr ss:[esp+0x4]
00405061  53                                    push ebx
00405062  8B 9C 24 04 00 00 00                  mov ebx, dword ptr ss:[esp+0x4]
00405069  89 9C 24 08 00 00 00                  mov dword ptr ss:[esp+0x8], ebx
00405070  8B 84 24 04 00 00 00                  mov eax, dword ptr ss:[esp+0x4]
00405077  50                                    push eax
00405078  8B 84 24 04 00 00 00                  mov eax, dword ptr ss:[esp+0x4]
0040507F  89 84 24 08 00 00 00                  mov dword ptr ss:[esp+0x8], eax
00405086  51                                    push ecx
00405087  8B 8C 24 08 00 00 00                  mov ecx, dword ptr ss:[esp+0x8]
0040508E  51                                    push ecx
0040508F  8B 8C 24 04 00 00 00                  mov ecx,dword ptr ss:[esp+0x4]
00405096  89 8C 24 0C 00 00 00                  mov dword ptr ss:[esp+0xC], ecx
0040509D  8B 84 24 08 00 00 00                  mov eax, dword ptr ss:[esp+0x8]
004050A4  50                                    push eax
004050A5  8B 04 24                              mov eax, dword ptr ss:[esp]
004050A8  89 84 24 0C 00 00 00                  mov dword ptr ss:[esp+0xC], eax
004050AF  5B                                    pop ebx
004050B0  58                                    pop eax
004050B1  59                                    pop ecx
*/
  UCHAR xxcode[] = {
      0x50, 0x8B, 0x04, 0x24, 0x50, 0x8B, 0x04, 0x24, 0x89, 0x84, 0x24, 0x04,
      0x00, 0x00, 0x00, 0x53, 0x8B, 0x9C, 0x24, 0x04, 0x00, 0x00, 0x00, 0x53,
      0x8B, 0x9C, 0x24, 0x04, 0x00, 0x00, 0x00, 0x89, 0x9C, 0x24, 0x08, 0x00,
      0x00, 0x00, 0x8B, 0x84, 0x24, 0x04, 0x00, 0x00, 0x00, 0x50, 0x8B, 0x84,
      0x24, 0x04, 0x00, 0x00, 0x00, 0x89, 0x84, 0x24, 0x08, 0x00, 0x00, 0x00,
      0x51, 0x8B, 0x8C, 0x24, 0x08, 0x00, 0x00, 0x00, 0x51, 0x8B, 0x8C, 0x24,
      0x04, 0x00, 0x00, 0x00, 0x89, 0x8C, 0x24, 0x0C, 0x00, 0x00, 0x00, 0x8B,
      0x84, 0x24, 0x08, 0x00, 0x00, 0x00, 0x50, 0x8B, 0x04, 0x24, 0x89, 0x84,
      0x24, 0x0C, 0x00, 0x00, 0x00, 0x5B, 0x58, 0x59};

  uc_mem_map(uc, ADDRESS, 20 * 1024 * 1024, UC_PROT_ALL);

  // write patch
  if ((err = uc_mem_write(uc, ADDRESS, xxcode, sizeof(xxcode)))) {
    std::printf("> failed to write memory... reason = %d\n", err);
    return;
  }

  uint64_t r_esp = 0x0019FF28;
  uint64_t r_esp_base = r_esp & ~0xFFFull;
  // esp
  uc_mem_map(uc, r_esp_base, 0x1000, UC_PROT_ALL);
  // UCHAR empty[0x1000] = {0};
  // uc_mem_write(uc, r_esp_base, empty, sizeof(empty));

  int r_eax = 0x1;
  int r_ebx = 0x2;
  int r_ecx = 0x3;

  uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
  uc_reg_write(uc, UC_X86_REG_EBX, &r_ebx);
  uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
  uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
  // tracing all instruction by having @begin > @end
  // uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

  if ((err =
           uc_hook_add(uc, &invalid_mem_hook,
                       UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                           UC_HOOK_MEM_FETCH_UNMAPPED,
                       (void *)&invalid_mem, NULL, 1, 0))) {
    std::printf("> uc_hook_add error, reason = %d\n", err);
    return;
  }

  // tracing all memory READ/WRITE access (with @begin > @end)
  uc_hook_add(uc, &hook_mem_trace_read, UC_HOOK_MEM_READ, hook_mem64, NULL, 1,
              0);
  uc_hook_add(uc, &hook_mem_trace_write, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1,
              0);

  // emulate machine code in infinite time
  err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(xxcode), 0, 0);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n", err,
           uc_strerror(err));
  }

  // now print out some registers
  printf(">>> Emulation done. Below is the CPU context\n");

  uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
  uc_reg_read(uc, UC_X86_REG_EBX, &r_ebx);
  uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
  int r_return_esp = 0;
  uc_reg_read(uc, UC_X86_REG_ESP, &r_return_esp);
  printf(">>> EAX = 0x%x\n", r_eax);
  printf(">>> EBX = 0x%x\n", r_ebx);
  printf(">>> ECX = 0x%x\n", r_ecx);
  printf(">>> ESP = 0x%x\n", r_return_esp);

  for (int i = r_return_esp; i <= r_esp; i += 4) {
    // read esp
    if (!uc_mem_read(uc, i, &tmp, sizeof(tmp)))
      printf(">>> Read esp from [0x%x] = 0x%x\n", i, tmp);
    else
      printf(">>> Failed to read esp from [0x%x]\n", r_esp);
  }

  uc_close(uc);
}

int main() {
  test_i386_map_ptr();
  test_i386_1();
  return 0;
}
