#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include "vm/page.h"

typedef int pid_t;
typedef int mapid_t;

struct vm_entry *check_address(void *);
void check_valid_buffer (void *, unsigned, bool);
void check_valid_string(void *str);
void syscall_init (void);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapid);

#endif /* userprog/syscall.h */
