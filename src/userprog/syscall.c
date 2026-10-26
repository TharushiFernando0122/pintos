#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
struct lock filesys_lock;  /*T: Only the holder may use the file system (also used in process.c). */

/*T: Checking user pointers. */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void check_valid_ptr (const void *ptr);
static void check_valid_buf (const void *buffer, unsigned size);
static void check_valid_str (const char *str);

/*T: System call implementations. */
static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

/*T: File descriptor helpers. */
static struct process_file *get_file (int fd);
static int allocate_fd (void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

/*T: Reads a byte at user address UADDR. Returns the byte, or -1 on a
     fault. Not used: we check pointers before using them instead. */
static int
get_user (const uint8_t *uaddr)
{
  if (!is_user_vaddr (uaddr))
    return -1;
  
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/*T: Writes BYTE to user address UDST. Returns true on success, false
     on a fault. Not used: we check pointers before using them instead. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if (!is_user_vaddr (udst))
    return false;
  
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/*T: Kills the process unless PTR is a mapped user address. */
static void
check_valid_ptr (const void *ptr)
{
  /*T: NULL is never valid. */
  if (ptr == NULL)
    sys_exit (-1);
  
  /*T: Kernel memory is off limits. */
  if (!is_user_vaddr (ptr))
    sys_exit (-1);
  
  /*T: The page must actually exist in this process. */
  if (pagedir_get_page (thread_current ()->pagedir, ptr) == NULL)
    sys_exit (-1);
}

/*T: Kills the process unless every byte of BUFFER is valid user memory. */
static void
check_valid_buf (const void *buffer, unsigned size)
{
  /*T: Nothing to read or write, so nothing to check. */
  if (size == 0)
    return;
    
  /*T: NULL is never valid. */
  if (buffer == NULL)
    sys_exit (-1);
  
  /*T: The start must be a user address. */
  if (!is_user_vaddr (buffer))
    sys_exit (-1);
    
  char *start_ptr = (char *) buffer;
  char *end_ptr = start_ptr + size - 1;
  
  /*T: The end must not wrap around or reach into kernel memory. */
  if (end_ptr < start_ptr || !is_user_vaddr (end_ptr))
    sys_exit (-1);
  
  /*T: Check one address on every page, so an unmapped page in the
       middle is caught too. */
  check_valid_ptr (buffer);
  for (char *p = (char *) pg_round_down (buffer) + PGSIZE; p <= end_ptr; p += PGSIZE)
    check_valid_ptr (p);
  check_valid_ptr (end_ptr);
}

/*T: Kills the process unless the whole string, up to its '\0', is
     valid user memory. */
static void
check_valid_str (const char *str)
{
  /*T: NULL is never valid. */
  if (str == NULL)
    sys_exit (-1);
  
  /*T: The start must be a user address. */
  if (!is_user_vaddr (str))
    sys_exit (-1);
    
  const char *current_char = str;
  
  /*T: Check each character before reading it. */
  while (true)
  {
    /*T: This character must be a user address... */
    if (!is_user_vaddr (current_char))
      sys_exit (-1);
    
    /*T: ...on a page that exists. */
    if (pagedir_get_page (thread_current ()->pagedir, current_char) == NULL)
      sys_exit (-1);
    
    /*T: Safe to read now. */
    if (*current_char == '\0')
      break;
      
    current_char++;
  }
}

/*T: Reads the call number and arguments from the user stack, checks
     them, and runs the call. */
static void
syscall_handler (struct intr_frame *f) 
{
  int *stack_ptr = (int *) f->esp;
  
  /*T: All 4 bytes of the call number must be readable. */
  check_valid_ptr (stack_ptr);
  check_valid_ptr ((char *)stack_ptr + 3);  /*T: ...including the last one. */
  
  int syscall_num = *stack_ptr;
  
  switch (syscall_num)
  {
    case SYS_HALT:
      sys_halt ();
      break;
      
    case SYS_EXIT:
      /*T: Check the status argument. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      sys_exit (*(stack_ptr + 1));
      break;
      
    case SYS_EXEC:
      /*T: Check the command line pointer and the string itself. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      check_valid_str ((char *) *(stack_ptr + 1));
      f->eax = sys_exec ((char *) *(stack_ptr + 1));
      break;
      
    case SYS_WAIT:
      /*T: Check the pid argument. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      f->eax = sys_wait (*(stack_ptr + 1));
      break;
      
    case SYS_CREATE:
      /*T: Check the file name and size, then the name string. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      check_valid_ptr (stack_ptr + 2);
      check_valid_ptr ((char *)(stack_ptr + 2) + 3);
      check_valid_str ((char *) *(stack_ptr + 1));
      f->eax = sys_create ((char *) *(stack_ptr + 1), *(stack_ptr + 2));
      break;
      
    case SYS_REMOVE:
      /*T: Check the file name pointer and the string itself. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      check_valid_str ((char *) *(stack_ptr + 1));
      f->eax = sys_remove ((char *) *(stack_ptr + 1));
      break;
      
    case SYS_OPEN:
      /*T: Check the file name pointer and the string itself. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      check_valid_str ((char *) *(stack_ptr + 1));
      f->eax = sys_open ((char *) *(stack_ptr + 1));
      break;
      
    case SYS_FILESIZE:
      /*T: Check the fd argument. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      f->eax = sys_filesize (*(stack_ptr + 1));
      break;
      
    case SYS_READ:
      /*T: Check fd, buffer and size, then the whole buffer. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      check_valid_ptr (stack_ptr + 2);
      check_valid_ptr ((char *)(stack_ptr + 2) + 3);
      check_valid_ptr (stack_ptr + 3);
      check_valid_ptr ((char *)(stack_ptr + 3) + 3);
      check_valid_buf ((void *) *(stack_ptr + 2), *(stack_ptr + 3));
      f->eax = sys_read (*(stack_ptr + 1), (void *) *(stack_ptr + 2), *(stack_ptr + 3));
      break;
      
    case SYS_WRITE:
      /*T: Check fd, buffer and size, then the whole buffer. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      check_valid_ptr (stack_ptr + 2);
      check_valid_ptr ((char *)(stack_ptr + 2) + 3);
      check_valid_ptr (stack_ptr + 3);
      check_valid_ptr ((char *)(stack_ptr + 3) + 3);
      check_valid_buf ((void *) *(stack_ptr + 2), *(stack_ptr + 3));
      f->eax = sys_write (*(stack_ptr + 1), (void *) *(stack_ptr + 2), *(stack_ptr + 3));
      break;
      
    case SYS_SEEK:
      /*T: Check the fd and position arguments. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      check_valid_ptr (stack_ptr + 2);
      check_valid_ptr ((char *)(stack_ptr + 2) + 3);
      sys_seek (*(stack_ptr + 1), *(stack_ptr + 2));
      break;
      
    case SYS_TELL:
      /*T: Check the fd argument. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      f->eax = sys_tell (*(stack_ptr + 1));
      break;
      
    case SYS_CLOSE:
      /*T: Check the fd argument. */
      check_valid_ptr (stack_ptr + 1);
      check_valid_ptr ((char *)(stack_ptr + 1) + 3);
      sys_close (*(stack_ptr + 1));
      break;
      
    default:
      /*T: Unknown call number: kill the process. */
      sys_exit (-1);
      break;
  }
}

/*T: Powers off the machine. */
static void
sys_halt (void)
{
  shutdown_power_off ();
}

/*T: Ends the current process with STATUS. */
static void
sys_exit (int status)
{
  struct thread *current_thread = thread_current ();
  
  /*T: The exact message the tests check for. */
  printf ("%s: exit(%d)\n", current_thread->name, status);
  
  /*T: Save the status so the parent can get it from wait(). */
  if (current_thread->child_process != NULL)
  {
    current_thread->child_process->exit_status = status;
  }
  
  thread_exit ();
}

/*T: Starts a program; returns its pid, or -1 if it can't load. */
static pid_t
sys_exec (const char *cmd_line)
{
  /*T: Don't take filesys_lock here. The child needs it to load, and
       we're about to wait for that load, so we'd both be stuck. */
  return process_execute (cmd_line);
}

/*T: Waits for child PID and returns its exit status. */
static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

/*T: Creates FILE with INITIAL_SIZE bytes; does not open it. */
static bool
sys_create (const char *file, unsigned initial_size)
{
  /*T: A NULL file name kills the process. */
  if (file == NULL)
    sys_exit (-1);
  
  lock_acquire (&filesys_lock);
  bool creation_success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  
  return creation_success;
}

/*T: Deletes FILE. Processes that have it open can keep using it. */
static bool
sys_remove (const char *file)
{
  /*T: A NULL file name kills the process. */
  if (file == NULL)
    sys_exit (-1);
  
  lock_acquire (&filesys_lock);
  bool removal_success = filesys_remove (file);
  lock_release (&filesys_lock);
  
  return removal_success;
}

/*T: Opens FILE; returns a new fd, or -1. */
static int
sys_open (const char *file)
{
  if (file == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  struct file *opened_file = filesys_open (file);
  lock_release (&filesys_lock);
  
  /*T: No such file. */
  if (opened_file == NULL)
    return -1;
  
  /*T: One list entry per open file. */
  struct process_file *proc_file = malloc (sizeof (struct process_file));
  if (proc_file == NULL)
  {
    file_close (opened_file);
    return -1;
  }
  
  /*T: Give it the next fd number. */
  proc_file->file = opened_file;
  proc_file->fd = allocate_fd ();
  
  /*T: Only this process can use the new fd. */
  list_push_back (&thread_current ()->file_name_list, &proc_file->elem);
  
  return proc_file->fd;
}

/*T: Size of the open file in bytes, or -1 for a bad fd. */
static int
sys_filesize (int fd)
{
  struct process_file *proc_file = get_file (fd);
  if (proc_file == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int file_len = file_length (proc_file->file);
  lock_release (&filesys_lock);
  
  return file_len;
}

/*T: Reads up to SIZE bytes; fd 0 is the keyboard. */
static int
sys_read (int fd, void *buffer, unsigned size)
{
  /*T: Keyboard. */
  if (fd == 0)
  {
    unsigned byte_idx;
    uint8_t *read_buf = (uint8_t *) buffer;
    for (byte_idx = 0; byte_idx < size; byte_idx++)
    {
      read_buf[byte_idx] = input_getc ();
    }
    return size;
  }
  
  /*T: Regular file. */
  struct process_file *proc_file = get_file (fd);
  if (proc_file == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int read_bytes = file_read (proc_file->file, buffer, size);
  lock_release (&filesys_lock);
  
  return read_bytes;
}

/*T: Writes up to SIZE bytes; fd 1 is the console. */
static int
sys_write (int fd, const void *buffer, unsigned size)
{
  /*T: Console: one putbuf() call, so lines from different processes
       don't mix. */
  if (fd == 1)
  {
    putbuf (buffer, size);
    return size;
  }
  
  /*T: Regular file. */
  struct process_file *proc_file = get_file (fd);
  if (proc_file == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int written_bytes = file_write (proc_file->file, buffer, size);
  lock_release (&filesys_lock);
  
  return written_bytes;
}

/*T: Moves the read/write position; past the end is allowed. */
static void
sys_seek (int fd, unsigned position)
{
  struct process_file *proc_file = get_file (fd);
  if (proc_file == NULL)
    return;
  
  lock_acquire (&filesys_lock);
  file_seek (proc_file->file, position);
  lock_release (&filesys_lock);
}

/*T: Current read/write position. */
static unsigned
sys_tell (int fd)
{
  struct process_file *proc_file = get_file (fd);
  if (proc_file == NULL)
    return 0;
  
  lock_acquire (&filesys_lock);
  unsigned file_position = file_tell (proc_file->file);
  lock_release (&filesys_lock);
  
  return file_position;
}

/*T: Closes FD; does nothing for a bad fd. */
static void
sys_close (int fd)
{
  struct process_file *proc_file = get_file (fd);
  if (proc_file == NULL)
    return;
  
  lock_acquire (&filesys_lock);
  file_close (proc_file->file);
  lock_release (&filesys_lock);
  
  /*T: Remove it from our list and free it. */
  list_remove (&proc_file->elem);
  free (proc_file);
}

/*T: Finds FD in this process's list, or returns NULL. */
static struct process_file *
get_file (int fd)
{
  struct thread *current_thread = thread_current ();
  struct list_elem *list_item;
  
  /*T: Only this process's own files. */
  for (list_item = list_begin (&current_thread->file_name_list); 
       list_item != list_end (&current_thread->file_name_list);
       list_item = list_next (list_item))
  {
    struct process_file *proc_file = list_entry (list_item, struct process_file, elem);
    if (proc_file->fd == fd)
      return proc_file;
  }
  
  return NULL;
}

/*T: Next fd number. Shared by all processes, so one is never reused. */
static int
allocate_fd (void)
{
  static int fd_counter = 2;  /*T: 0 and 1 are the keyboard and console. */
  return fd_counter++;
}

/*T: Lets exception.c end a process the same way exit() does. */
void
syscall_exit (int status)
{
  sys_exit (status);
}