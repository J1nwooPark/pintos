/* -*- c -*- */

#include <syscall.h>
#include <stdio.h>
#include "fslib.h"

static char buf[512];

static size_t
return_block_size (void) 
{
  return sizeof buf;
}

void
test_main (void) 
{
  size_t i;
  
#ifdef DIRECTORY
  CHECK (mkdir (DIRECTORY), "mkdir %s", DIRECTORY);
#define DIR_PREFIX DIRECTORY "/"
#else
#define DIR_PREFIX ""
#endif
  for (i = 0; i < FILE_CNT; i++) 
    {
      char filename[128];
      snprintf (filename, sizeof filename, "%sfile%zu", DIR_PREFIX, i);

      msg ("creating and checking \"%s\"", filename);

      quiet = true;
      seq_test (filename,
                buf, sizeof buf, sizeof buf,
                return_block_size, NULL); 
      quiet = false;
    }
}