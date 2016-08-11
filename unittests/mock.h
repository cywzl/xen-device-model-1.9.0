#ifndef _QEMU_MOCK_H_
#define _QEMU_MOCK_H_

/* interface inspired by CMocka*/

#define with_return(func, ret)     _with_return(#func, ret, __FILE__, __LINE__)
#define with_return_num(func, ret) _with_return(#func, (void*) (long) (ret), __FILE__, __LINE__)
void _with_return(const char *f, const void *ret, const char *fn, int ln);

#define mock()             _mock(__func__, __FILE__, __LINE__)
#define mock_num() ((long) _mock(__func__, __FILE__, __LINE__))
const void *_mock(const char *f, const char *fn, int ln);

int mock_check_left(void);

#endif
