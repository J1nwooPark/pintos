#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "devices/shutdown.h"
#include "devices/input.h"

/* Lock used to execute file system functions. */
static struct lock file_lock;

static void syscall_handler (struct intr_frame *);

void
check_address(void *esp)
{
  if (esp < (void *)0x08048000 || PHYS_BASE <= esp)
    exit(-1);
}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = f->esp;
  check_address(esp);
  int syscall_num = *(int *)esp;
  uint32_t ret;

  switch (syscall_num) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_address(esp + 4);
      exit(*(int *)(esp + 4));
      break;
    case SYS_EXEC:
      check_address(*(char **)(esp + 4));
      ret = exec(*(char **)(esp + 4));
      f->eax = ret;
      break;
    case SYS_WAIT:
      check_address(esp + 4);
      ret = wait(*(int *)(esp + 4));
      f->eax = ret;
      break;
    case SYS_CREATE:
      check_address(esp + 8);
      check_address(*(char **)(esp + 4));
      
      lock_acquire (&file_lock);
      ret = create(*(char **)(esp + 4), *(unsigned *)(esp + 8));
      lock_release (&file_lock);
      
      f->eax = ret;
      break;
    case SYS_REMOVE:
      check_address(esp + 4);
      check_address(*(char **)(esp + 4));

      lock_acquire (&file_lock);
      ret = remove(*(char **)(esp + 4));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_OPEN:
      check_address(esp + 4);
      check_address(*(char **)(esp + 4));
      
      lock_acquire (&file_lock);
      ret = open(*(char **)(esp + 4));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_FILESIZE:
      check_address(esp + 4);

      lock_acquire (&file_lock);
      ret = filesize(*(int *)(esp + 4));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_READ:
      check_address(esp + 12);
      check_address(*(void **)(esp + 8));

      lock_acquire (&file_lock);
      ret = read(*(int *)(esp + 4), *(void **)(esp + 8), *(unsigned *)(esp + 12));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_WRITE:
      check_address(esp + 12);
      check_address(*(void **)(esp + 8));

      lock_acquire (&file_lock);
      ret = write(*(int *)(esp + 4), *(void **)(esp + 8), *(unsigned *)(esp + 12));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_SEEK:
      check_address(esp + 8);

      lock_acquire (&file_lock);
      seek(*(int *)(esp + 4), *(unsigned *)(esp + 8));
      lock_release (&file_lock);
      break;
    case SYS_TELL:
      check_address(esp + 4);

      lock_acquire (&file_lock);
      ret = tell(*(int *)(esp + 4));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_CLOSE:
      check_address(esp + 4);

      lock_acquire (&file_lock);
      close(*(int *)(esp + 4));
      lock_release (&file_lock);
      break;
  }
}

void 
halt (void)
{
  shutdown_power_off();
}

void 
exit (int status)
{
  struct thread *t = thread_current();
  int i;

  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  for (i = 2; i < 128; i++)
    close(i);
  file_close(t->executing_file);
  thread_exit();
}

pid_t 
exec (const char *file)
{
  struct thread *cur = thread_current();
  tid_t child_tid = process_execute(file);
  struct list_elem *e;


  for (e = list_begin(&cur->childs); e != list_end(&cur->childs); e = list_next(e))
  {
    struct thread *temp = list_entry (e, struct thread, child_elem);
    if (temp->tid == child_tid)
    {
      sema_down(&(temp->exec_sema));
      if (temp->is_loaded)
        return child_tid;
    }
  } 
  return -1;
}

int 
wait (pid_t pid)
{
  return process_wait(pid);
}

bool 
create (const char *file, unsigned initial_size)
{
  return filesys_create(file, initial_size);
}

bool 
remove (const char *file)
{
  return filesys_remove(file);
}

int 
open (const char *file)
{
  struct file *opened_file = filesys_open(file);
  struct thread *t = thread_current();

  if (opened_file == NULL)
    return -1;
  t->file_descriptor[t->file_next_idx] = opened_file;
  return t->file_next_idx++;
}

int 
filesize (int fd)
{
  struct thread *t = thread_current();
  struct file *idxed_file = t->file_descriptor[fd];
  
  if (idxed_file == NULL)
    return -1;
  return file_length(idxed_file);
}

int 
read (int fd, void *buffer, unsigned length)
{
  struct thread *t = thread_current();
  struct file *toread_file;
  unsigned i;

  if (fd == 0)
  {
    for (i = 0; i < length; i++) 
      *(char *)(buffer + i) = input_getc();
    return length;
  }
  toread_file = t->file_descriptor[fd];
  if (toread_file == NULL)
    return -1;
  return file_read(toread_file, buffer, length);
}

int 
write (int fd, const void *buffer, unsigned length)
{
  struct thread *t = thread_current();
  struct file *towrite_file;

  if (fd == 1)
  {
    putbuf(buffer, length);
    return length;
  }
  towrite_file = t->file_descriptor[fd];
  if (towrite_file == NULL)
    return -1;
  return file_write(towrite_file, buffer, length);
}

void 
seek (int fd, unsigned position)
{
  struct thread *t = thread_current();
  struct file *toseek_file;
    
  toseek_file = t->file_descriptor[fd];
  if (toseek_file == NULL)
    return;
  file_seek(toseek_file, position);
  return;
}

unsigned 
tell (int fd)
{
  struct thread *t = thread_current();
  struct file *totell_file;
    
  totell_file = t->file_descriptor[fd];
  return file_tell(totell_file);
}

void 
close (int fd)
{
  struct thread *t = thread_current();
  file_close(t->file_descriptor[fd]);
  t->file_descriptor[fd] = NULL;
  if (fd + 1 == t->file_next_idx)
    t->file_next_idx--;
}