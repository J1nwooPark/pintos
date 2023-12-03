#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/palloc.h"

struct frame {
  void *addr;
  struct vm_entry *vme;
  struct thread *t;
  struct list_elem elem;
};

void lru_list_init (void);
void add_frame (struct frame *);
void del_frame (struct frame *);

struct frame* alloc_frame (enum palloc_flags);
void free_frame (void *);

struct list_elem *get_next_clock_frame(void);

void *try_free_frame (enum palloc_flags);

#endif /* vm/frame.h */
