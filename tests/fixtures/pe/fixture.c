typedef unsigned long long u64;
typedef unsigned int u32;
__declspec(dllimport) void __stdcall Sleep(u32 ms);
__declspec(dllimport) u32 __stdcall GetTickCount(void);
__declspec(dllimport) int __stdcall MessageBeep(u32 type);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);

/* The linker's delay-load thunks call this; a real one comes from the CRT. */
void *__delayLoadHelper2(void *descriptor, void **slot) { (void)descriptor; return *slot; }

static int counter;
static void __stdcall on_thread(void *module, u32 reason, void *reserved) { (void)module; (void)reserved; counter += (int)reason; }

u32 _tls_index;
#pragma section(".tls$AAA", read, write)
#pragma section(".tls$ZZZ", read, write)
#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
__declspec(allocate(".tls$AAA")) char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end = 0;
typedef void (__stdcall *tls_cb)(void *, u32, void *);
__declspec(allocate(".CRT$XLA")) const tls_cb __xl_a = 0;
__declspec(allocate(".CRT$XLB")) const tls_cb __xl_b = on_thread;
__declspec(allocate(".CRT$XLZ")) const tls_cb __xl_z = 0;
const struct { u64 start, end, index, callbacks; u32 zero_fill, characteristics; } _tls_used = {
    (u64)&_tls_start, (u64)&_tls_end, (u64)&_tls_index, (u64)(&__xl_a + 1), 0, 0
};

const char *message = "hello from the cffx fixture";
__declspec(dllexport) int fixture_add(int a, int b) { return a + b; }
__declspec(dllexport) int fixture_answer(void) { return 42; }

int entry(void) {
    Sleep(0);
    if (GetTickCount() == 0xffffffff) MessageBeep(0);
    return fixture_add(GetSystemMetrics(0), counter) + (message[0] != 'h');
}
