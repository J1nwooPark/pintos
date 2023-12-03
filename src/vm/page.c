#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <string.h>

extern struct lock file_lock;

void vm_init (struct hash *vm)
{
  hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

void vm_destroy (struct hash *vm)
{
  hash_destroy(vm, vm_destroy_func);
}

bool insert_vme (struct hash *vm, struct vm_entry *vme)
{
  struct hash_elem *e = hash_insert(vm, &vme->elem);
  if (e == NULL) return true;
  return false;
}

bool delete_vme (struct hash *vm, struct vm_entry *vme)
{
  struct hash_elem *e = hash_delete(vm, &vme->elem);
  if (e != NULL) return true;
  return false;
}

struct vm_entry *find_vme (void *vaddr)
{
  struct vm_entry vme;
  struct hash_elem *e;
  struct thread *t = thread_current();

  vme.vaddr = pg_round_down(vaddr);
  e = hash_find(&t->vm, &vme.elem);
  if (e == NULL) return NULL;
  return hash_entry(e, struct vm_entry, elem);
}

unsigned vm_hash_func (const struct hash_elem *e, void *aux)
{
  struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
  return hash_int((int)vme->vaddr);
}

bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux)   
{
  struct vm_entry *vme_a = hash_entry(a, struct vm_entry, elem);
  struct vm_entry *vme_b = hash_entry(b, struct vm_entry, elem);
  void *vaddr_a = vme_a->vaddr;
  void *vaddr_b = vme_b->vaddr;
  return vaddr_a < vaddr_b;
}

void vm_destroy_func (struct hash_elem *e, void *aux)
{
  struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
  free_frame(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
  free(vme);
}

bool load_file (void *kpage, struct vm_entry *vme)
{
  bool is_holding_lock = lock_held_by_current_thread(&file_lock);

  if (!is_holding_lock) lock_acquire (&file_lock);
  if (file_read_at (vme->file, kpage, vme->page_read_bytes, vme->ofs) != (int) vme->page_read_bytes)
  {
    lock_release (&file_lock);
    return false; 
  }
  memset (kpage + vme->page_read_bytes, 0, vme->page_zero_bytes);
  if (!is_holding_lock) lock_release (&file_lock);
  return true;
}