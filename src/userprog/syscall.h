#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include <list.h>

/*T: A process id; same number as its thread id. */
typedef int pid_t;

/*T: Shared by a parent and one child. It outlives the child, so the
     parent can still read the exit status. */
struct child_process
{
  int pid;                      /*T: The child's pid. */
  int exit_status;              /*T: What the child passed to exit(), or -1 if killed. */
  bool waited;                  /*T: Set on the first wait, so a second wait returns -1. */
  bool exited;                  /*T: Has the child exited? */
  bool load_success;            /*T: Did the child load successfully? */
  bool parent_alive;            /*T: If false, the child frees this record itself. */
  struct list_elem elem;        /*T: Element in the parent's child list. */
  struct semaphore wait_sema;   /*T: Raised once when the child exits. */
  struct semaphore load_sema;   /*T: Raised once the child knows if loading worked. */
};

/*T: One open file of a process. */
struct process_file
{
  struct file *file;            /*T: The open file. */
  int fd;                       /*T: The number the user program uses for it. */
  struct list_elem elem;        /*T: Element in the process's open-file list. */
};

/*T: Only one thread at a time may run file system code. */
extern struct lock filesys_lock;

void syscall_init (void);
void syscall_exit (int status);

#endif /* userprog/syscall.h */