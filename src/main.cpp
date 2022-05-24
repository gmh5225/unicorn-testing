#include <iostream>
#include <string.h>
#include <unicorn/unicorn.h>

// memory address where emulation starts
#define ADDRESS 0x1000000

// code to be emulated
#define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx;

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

  // Uncomment below code to stop the emulation using uc_emu_stop()
  // if (address == 0x1000009)
  //    uc_emu_stop(uc);
}

static void test_i386_map_ptr(void) {
  uc_engine *uc;
  uc_err err;
  uint32_t tmp;
  uc_hook trace1, trace2;
  void *mem;

  int r_ecx = 0x1234; // ECX register
  int r_edx = 0x7890; // EDX register

  printf("===================================\n");
  printf("Emulate i386 code - use uc_mem_map_ptr()\n");

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
  if (err) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return;
  }

  // malloc 2MB memory for this emulation
  mem = calloc(1, 2 * 1024 * 1024);
  if (mem == NULL) {
    printf("Failed to malloc()\n");
    return;
  }

  uc_mem_map_ptr(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL, mem);

  // write machine code to be emulated to memory
  if (!memcpy(mem, X86_CODE32, sizeof(X86_CODE32) - 1)) {
    printf("Failed to write emulation code to memory, quit!\n");
    return;
  }

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

  // emulate machine code in infinite time
  err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n", err,
           uc_strerror(err));
  }

  // now print out some registers
  printf(">>> Emulation done. Below is the CPU context\n");

  uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
  printf(">>> ECX = 0x%x\n", r_ecx);
  printf(">>> EDX = 0x%x\n", r_edx);

  // read from memory
  if (!uc_mem_read(uc, ADDRESS, &tmp, sizeof(tmp)))
    printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS, tmp);
  else
    printf(">>> Failed to read 4 bytes from [0x%x]\n", ADDRESS);

  uc_close(uc);
  free(mem);
}

int main() {
  test_i386_map_ptr();
  return 0;
}
