#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include <list.h>

/*T: A process id-same number as its thread id*/
typedef int pid_t;

/*T: Shared by a parent and one child. It outlives the child. So the
     parent can still read the exit status*/
struct child_process
{
  int pid;                      /*T: The child's pid*/
  int exit_status;              /*T: What the child passed to exit(), or -1 if killed*/
  bool waited;                  
  bool exited;                  
  bool load_success;            
  bool parent_alive;            
  struct list_elem elem;        
  struct semaphore wait_sema;   /*T: Raised once when the child exits*/
  struct semaphore load_sema;   /*T: Raised once the child knows if loading worked*/
};

/*T: One open file of a process. */
struct process_file
{
  struct file *file;            /*T: Open file*/
  int fd;                       /*T: Number the user program uses for it*/
  struct list_elem elem;        /*T: Element in the process's open-file list*/
};

/*T: Only one thread at a time may run file system code*/
extern struct lock filesys_lock;

void syscall_init (void);
void syscall_exit (int status);

#endif /* userprog/syscall.h */