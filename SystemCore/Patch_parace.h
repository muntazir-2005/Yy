#ifndef PTRACE_H
#define PTRACE_H

#include <sys/types.h>
#include <sys/cdefs.h>

#define PT_DENY_ATTACH 31  // الطلب اللي يمنع attach للdebugger

#ifdef __cplusplus
extern "C" {
#endif

int ptrace(int request, pid_t pid, caddr_t addr, int data);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_H */
