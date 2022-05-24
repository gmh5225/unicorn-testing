#include <iostream>
#include <string.h>
#include <unicorn/unicorn.h>

// memory address where emulation starts
#define ADDRESS 0x41F000

// code to be emulated
unsigned char X86_CODE32[] = {
    0x8F, 0x05, 0x2D, 0xF0, 0x41, 0x00, 0x50, 0xB8, 0xCC, 0xCC, 0xCC,
    0xCC, 0x8D, 0x80, 0x9C, 0x8F, 0xDB, 0x74, 0x87, 0x05, 0x1B, 0xF0,
    0x41, 0x00, 0x58, 0x90, 0x90, 0xBB, 0xBB, 0xBB, 0xBB, 0x00, 0x50,
    0x66, 0xB8, 0xEB, 0xE9, 0x66, 0x87, 0x05, 0x1B, 0xF0, 0x41, 0x00,
    0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0x87, 0x04, 0x24, 0xC3};

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
  // if (address == 0x1000009)
  //    uc_emu_stop(uc);
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
    // hack espdata
    // 0x19ff28
    if (0x19ff28 == address) {
      int data = 0x0040105E;
      int err = uc_mem_write(uc, 0x19ff28, &data, 4);
      if (err) {
        printf("hook_mem64:uc_mem_write esp failed!\n");
      }
    }
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

  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
  if ((err = uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32)))) {
    std::printf("> failed to write memory... reason = %d\n", err);
    return;
  }

  uint64_t r_esp = 0x0019FF28;
  uint64_t r_esp_base = r_esp & ~0xFFFull;

  // map rsp
  uc_mem_map(uc, r_esp_base, 2 * 1024 * 1024, UC_PROT_ALL);

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
  err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32), 0, 0);
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

  // read esp
  if (!uc_mem_read(uc, r_esp, &tmp, sizeof(tmp)))
    printf(">>> Read esp from [0x%x] = 0x%x\n", r_esp, tmp);
  else
    printf(">>> Failed to read esp from [0x%x]\n", r_esp);

  uc_close(uc);
}

int main() {
  test_i386_map_ptr();
  return 0;
}
