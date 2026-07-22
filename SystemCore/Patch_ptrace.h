#ifndef SYS_PTRACE_H
#define SYS_PTRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#define PT_DENY_ATTACH 31

int ptrace(int request, pid_t pid, caddr_t addr, int data);

#ifdef __cplusplus
}
#endif

#endif /* SYS_PTRACE_H */
