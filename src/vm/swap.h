#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <hash.h>
#include "filesys/file.h"

void swap_init (void);
void swap_in (size_t, void *);
size_t swap_out (void *);

#endif /* vm/swap.h */
