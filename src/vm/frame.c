#include "vm/frame.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"

static struct list lru_list;
static struct lock lru_lock;
extern struct lock file_lock;
static struct list_elem *lru_clock;

void lru_list_init (void)
{
  list_init (&lru_list);
  lock_init(&lru_lock);
  lru_clock = NULL;
}

void add_frame (struct frame *f)
{
  lock_acquire (&lru_lock);
  list_push_back(&lru_list, &f->elem);
  lock_release (&lru_lock);
}

void del_frame (struct frame *f)
{
  bool is_holding_lock = lock_held_by_current_thread(&lru_lock);
  if (!is_holding_lock)
    lock_acquire (&lru_lock);
  list_remove (&f->elem);
  if (!is_holding_lock)
    lock_release (&lru_lock);
}

struct frame* alloc_frame (enum palloc_flags flags)
{
  void *kpage = palloc_get_page (flags);
  struct frame *f = malloc (sizeof *f);
    
  while (kpage == NULL)
    kpage = try_free_frame (flags);
  f->addr = kpage;
  f->t = thread_current();
  add_frame(f);
  return f;
}

void free_frame (void *addr)
{
  struct list_elem *e;
  struct frame *target = NULL;
  struct vm_entry *vme;
  bool isDirty;

  for (e = list_begin(&lru_list); e != list_end(&lru_list);
       e = list_next (e))
  {
    target = list_entry(e, struct frame, elem);
    if (target->addr == addr)
      break;
    else
      target = NULL;
  }
  if (target == NULL) return;

  vme = target->vme;
  switch (vme->type)
  {
    case 0:
      isDirty = pagedir_is_dirty(target->t->pagedir, vme->vaddr);   
      if (isDirty)
      {
        vme->swap_idx = swap_out (target->addr);
        vme->type = 2;
      }
      break;
    case 1:
      isDirty = pagedir_is_dirty(target->t->pagedir, vme->vaddr);
      bool is_holding_lock = lock_held_by_current_thread(&file_lock);
      if (!is_holding_lock) lock_acquire (&file_lock);
      if (isDirty)
        file_write_at(vme->file, vme->vaddr, vme->page_read_bytes, vme->ofs);
      if (!is_holding_lock) lock_release (&file_lock);
      break; 
    case 2:
      vme->swap_idx = swap_out (target->addr);
      break;
  }
  vme->is_loaded = false;
  palloc_free_page (target->addr);
  pagedir_clear_page (target->t->pagedir, vme->vaddr);
  del_frame (target);
  free (target);
}

struct list_elem *get_next_clock_frame()
{
  lru_clock = list_next(lru_clock);
  if (lru_clock == list_end(&lru_list))
    lru_clock = list_begin(&lru_list);
  return lru_clock;   
}

void *try_free_frame (enum palloc_flags flags)
{
  struct frame *f;

  lock_acquire (&lru_lock);
  while (1)
  {
    if (lru_clock == NULL)
      lru_clock = list_begin(&lru_list);
    f = list_entry (lru_clock, struct frame, elem);
    if (!f->vme->is_pinned && pagedir_is_accessed (f->t->pagedir, f->vme->vaddr) == false)
      break;
    pagedir_set_accessed (f->t->pagedir, f->vme->vaddr, false);
    lru_clock = get_next_clock_frame();
  }
  lru_clock = get_next_clock_frame();
  free_frame (f->addr);
  lock_release (&lru_lock);
  return palloc_get_page (flags);
}