#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = f->esp;
  if (!is_user_vaddr(esp)) exit(-1);
  int syscall_num = *(int *)esp;

  switch (syscall_num) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      if (!is_user_vaddr(esp + 4)) exit(-1);
      exit(*(int *)(esp + 4));
      break;
    case SYS_EXEC:
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      break;
    case SYS_WRITE:
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
  }
  thread_exit ();
}

void 
halt (void)
{

}

void 
exit (int status)
{
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

pid_t 
exec (const char *file)
{
  return -1;
}

int 
wait (pid_t pid)
{
  return -1;   
}

bool 
create (const char *file, unsigned initial_size)
{
  return -1;
    
}

bool 
remove (const char *file)
{
  return -1;
}

int 
open (const char *file)
{
  return -1;
}

int 
filesize (int fd)
{
  return -1;
}

int 
read (int fd, void *buffer, unsigned length)
{
    return -1;
}

int 
write (int fd, const void *buffer, unsigned length)
{
  
  return -1;
}

void 
seek (int fd, unsigned position)
{

}

unsigned 
tell (int fd)
{
    return -1;
}

void 
close (int fd)
{

}