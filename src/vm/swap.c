#include "vm/swap.h"
#include "threads/synch.h"
#include "bitmap.h"
#include "devices/block.h"

struct bitmap *swap_bitmap;
struct lock swap_lock;
extern struct lock file_lock;
struct block *swap_block;
block_sector_t swap_block_size;
size_t _bitmap_size;

void swap_init(void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  swap_block_size = block_size(swap_block);
  _bitmap_size = swap_block_size / 8;
  swap_bitmap = bitmap_create(_bitmap_size);
  lock_init(&swap_lock);
}

void swap_in (size_t idx, void *addr)
{
  int i;

  lock_acquire (&swap_lock);
  bool is_holding_lock = lock_held_by_current_thread(&file_lock);
  if (!is_holding_lock) lock_acquire (&file_lock);
  for (i = 0; i < 8; i++)
    block_read (swap_block, idx * 8 + i, addr + BLOCK_SECTOR_SIZE * i);
  if (!is_holding_lock) lock_release (&file_lock);
  bitmap_set (swap_bitmap, idx, false);
  lock_release (&swap_lock);
}

size_t swap_out (void *addr)
{
  size_t idx;
  int i;

  lock_acquire (&swap_lock);
  idx = bitmap_scan (swap_bitmap, 0, 1, false);
  if (idx == BITMAP_ERROR)
    exit(-1);
    
  bool is_holding_lock = lock_held_by_current_thread(&file_lock);
  if (!is_holding_lock) lock_acquire (&file_lock);
  for (i = 0; i < 8; i++)
    block_write (swap_block, idx * 8 + i, addr + BLOCK_SECTOR_SIZE * i);
  if (!is_holding_lock) lock_release (&file_lock);
  bitmap_set (swap_bitmap, idx, true);
  lock_release (&swap_lock);
  return idx;
}