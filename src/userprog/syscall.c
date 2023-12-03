#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* Lock used to execute file system functions. */
struct lock file_lock;

static void syscall_handler (struct intr_frame *);

struct vm_entry *
check_address(void *addr)
{
  struct vm_entry *vme;
  if (addr < (void *)0x08048000 || PHYS_BASE <= addr)
    exit(-1);
  vme = find_vme(addr);
  if (vme == NULL)  
    exit(-1);
  return vme;
}

void
check_valid_buffer (void *buffer, unsigned size, bool to_write)
{
  unsigned i;
    
  for (i = 0; i < size; i++)
  {
    struct vm_entry *vme = check_address(buffer + i);
    if (to_write && vme->writable == false)
      exit(-1);
  }
}

void
check_valid_string (void *str)
{
  while (1)
  {
    check_address(str);
    if (*(char *)str == '\0')
      break;
    str++;
  }  
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
  thread_current()->user_stack_pointer = esp;

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
      check_valid_string(*(char **)(esp + 4));
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
      check_valid_string(*(char **)(esp + 4));
      
      lock_acquire (&file_lock);
      ret = create(*(char **)(esp + 4), *(unsigned *)(esp + 8));
      lock_release (&file_lock);
      
      f->eax = ret;
      break;
    case SYS_REMOVE:
      check_valid_string(*(char **)(esp + 4));

      lock_acquire (&file_lock);
      ret = remove(*(char **)(esp + 4));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_OPEN:
      check_valid_string(*(char **)(esp + 4));
      
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
      check_valid_buffer(*(void **)(esp + 8), *(unsigned *)(esp + 12), true);

      lock_acquire (&file_lock);
      ret = read(*(int *)(esp + 4), *(void **)(esp + 8), *(unsigned *)(esp + 12));
      lock_release (&file_lock);

      f->eax = ret;
      break;
    case SYS_WRITE:
      check_address(esp + 12);
      check_valid_buffer(*(void **)(esp + 8), *(unsigned *)(esp + 12), false);

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
    case SYS_MMAP:
      check_address(esp + 8);
    
      lock_acquire (&file_lock);
      ret = mmap(*(int *)(esp + 4), *(void **)(esp + 8));
      lock_release (&file_lock);
          
      f->eax = ret;
      break;
    case SYS_MUNMAP:
      check_address(esp + 4);
          
      lock_acquire (&file_lock);
      munmap(*(int *)(esp + 4));
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

  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
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
  int ret;
  void *ptr;

  for (ptr = buffer; ptr < buffer + length; ptr += PGSIZE)
  {
    struct vm_entry *vme = find_vme(ptr);
    vme->is_pinned = true;
    if (!vme->is_loaded)
      vm_fault_handler(vme);
  }
  if (fd == 0)
  {
    for (i = 0; i < length; i++) 
      *(char *)(buffer + i) = input_getc();
    return length;
  }
  toread_file = t->file_descriptor[fd];
  if (toread_file == NULL)
    return -1;
  ret = file_read(toread_file, buffer, length);
  for (ptr = buffer; ptr < buffer + length; ptr += PGSIZE)
  {
    struct vm_entry *vme = find_vme(ptr);
    vme->is_pinned = false;
  }
  return ret;
}

int 
write (int fd, const void *buffer, unsigned length)
{
  struct thread *t = thread_current();
  struct file *towrite_file;
  void *ptr;
  int ret;

  for (ptr = buffer; ptr < buffer + length; ptr += PGSIZE)
  {
    struct vm_entry *vme = find_vme(ptr);
    vme->is_pinned = true;
    if (!vme->is_loaded)
      vm_fault_handler(vme);
  }
  if (fd == 1)
  {
    putbuf(buffer, length);
    return length;
  }
  towrite_file = t->file_descriptor[fd];
  if (towrite_file == NULL)
    return -1;
  ret = file_write(towrite_file, buffer, length);
  for (ptr = buffer; ptr < buffer + length; ptr += PGSIZE)
  {
    struct vm_entry *vme = find_vme(ptr);
    vme->is_pinned = false;
  }
  return ret;
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
  if (fd > 255) return;
  struct thread *t = thread_current();
  file_close(t->file_descriptor[fd]);
  t->file_descriptor[fd] = NULL;
  if (fd + 1 == t->file_next_idx)
    t->file_next_idx--;
}

mapid_t
mmap (int fd, void *addr)
{
  struct thread* t = thread_current();
  struct file *tomap_file = t->file_descriptor[fd], *new_file;
  off_t len;
  void *page_start;
  int i, page_cnt;
    
  if (fd <= 1 || addr == 0 || tomap_file == NULL) 
    return -1;
  len = file_length(tomap_file);
  if (len == 0)
    return -1;
  page_cnt = (len / PGSIZE) + ((len % PGSIZE) ? 1 : 0);
  page_start = pg_round_down(addr);
  if (addr != page_start)
    return -1;
  for (i = 0; i < page_cnt; i++)
  {
    struct vm_entry *vme = find_vme(page_start + i * PGSIZE);
    if (vme != NULL)
      return -1;
  }
    
  new_file = file_reopen(tomap_file);
  struct mmap_file *mfile = malloc (sizeof *mfile);
  mfile->mapid = t->mmap_next_idx++;
  mfile->mapped_file = new_file;
  list_init(&mfile->vme_list);
  list_push_back(&t->mmap_list, &mfile->elem);

  for (i = 0; i < page_cnt; i++)
  {
    struct vm_entry *vme = malloc (sizeof *vme);
    vme->vaddr = page_start + i * PGSIZE;
    vme->type = 1;
    vme->file = new_file;
    vme->page_read_bytes = (len >= PGSIZE) ? PGSIZE : len;
    vme->page_zero_bytes = PGSIZE - vme->page_read_bytes;
    vme->ofs = i * PGSIZE;
    vme->writable = true;
    vme->is_pinned = false;
    vme->is_loaded = false;
    insert_vme(&t->vm, vme);
    list_push_back(&mfile->vme_list, &vme->mmap_elem);
    len -= PGSIZE;
  }
  return mfile->mapid;
}

void
munmap (mapid_t mapid)
{
  struct thread *t = thread_current();
  struct list_elem *e, *e2;

  for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list);
       e = list_next (e))
  {
    struct mmap_file *mfile = list_entry(e, struct mmap_file, elem);
    if (mfile->mapid == mapid)
    {
      for (e2 = list_begin(&mfile->vme_list); e2 != list_end(&mfile->vme_list);)
      {
        struct vm_entry *vme = list_entry(e2, struct vm_entry, mmap_elem);
        void *vaddr = vme->vaddr;
        bool isDirty = pagedir_is_dirty(t->pagedir, vaddr);

        if (isDirty)
          file_write_at(mfile->mapped_file, vaddr, vme->page_read_bytes, vme->ofs);
        e2 = list_remove(e2);
        free_frame (pagedir_get_page (t->pagedir, vaddr));
        delete_vme(&t->vm, vme);
        free(vme);
      }
      list_remove(e);
      file_close (mfile->mapped_file);
      free(mfile);
      return;
    }
  }
}
