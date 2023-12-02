#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"

struct vm_entry {
  void *vaddr;

  struct file* file;

  size_t page_read_bytes;
  size_t page_zero_bytes;
  off_t ofs;
  
  bool writable;
  size_t swap_idx;
  struct hash_elem elem;
  struct list_elem mmap_elem;
};

struct mmap_file {
  int mapid;
  struct file *mapped_file;
  struct list_elem elem;
  struct list vme_list;
};

void vm_init(struct hash *);
void vm_destroy (struct hash *);

bool insert_vme (struct hash *, struct vm_entry *);
bool delete_vme (struct hash *, struct vm_entry *);
struct vm_entry *find_vme (void *);

unsigned vm_hash_func (const struct hash_elem *, void *);
bool vm_less_func (const struct hash_elem *, const struct hash_elem *, void *);
void vm_destroy_func (struct hash_elem *, void *);

bool load_file (void *, struct vm_entry *);

#endif /* vm/page.h */
