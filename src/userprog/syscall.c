#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

int 
wait (pid_t pid)
{
  return -1;   
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
  int i;

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
    vme->file = new_file;
    vme->page_read_bytes = (len >= PGSIZE) ? PGSIZE : len;
    vme->page_zero_bytes = PGSIZE - vme->page_read_bytes;
    vme->ofs = i * PGSIZE;
    vme->writable = true;
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
        delete_vme(&t->vm, vme);
        free(vme);
      }
      e = list_remove(e);
      free(mfile);
      return;
    }
  }
}
