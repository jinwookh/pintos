#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
	/* While creating thread, if the thread failed to open the file,
		 return TID_ERROR.	*/
	//여기서는 child프로세스 실행중-> 부모가 있으면-> 차일드의 load상태확인
	struct thread *t = return_thread(tid); //current가 아닌, tid번호를 가진thread
	if(t->parent_tid!=NO_PARENT){ // child인 경우
		// main스레드의 경우 parent_tid를 NO_PARENT로 세팅해놨음
		if(t->cp->load==FAIL_LOAD)
			return TID_ERROR;
	}

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

	struct child_process *child = thread_current()->cp;
	if (success==false)
		child->load = FAIL_LOAD;
	else
		child->load = FINISH_LOAD;

/* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
	/*
		process_execute가 리턴해주는 child_tid를 이용해서
		쓰레드의 status를 가져온다.(child 쓰레드는 init_thread()에 의해 ready상태)
		위의 설명에 따르면 child_tid 쓰레드가 죽고 exit_status를 리턴할 때까지
		기다리는게 이 함수의 목적이다.
		 
		1. 커널이 child_tid 쓰레드를 종료하면(예외 때문에 죽은 것) -1을 리턴한다.
		2. 콜링 프로세스의 자식이 아니면 													-1을 리턴한다.
		3. child_tid 쓰레드가 유효하지 않으면											-1을 리턴한다.
		4. 이 함수가 주어진 쓰레드에 의해 이미 호출되었다면				-1을 리턴한다.

	*/
//process_wait (tid_t child_tid UNUSED) 
	int exit_status;
	/* 1. Kernel terminates child_tid thread */
	if(child_tid==TID_ERROR) return -1;

	/* 2. Check that is is calling process's child or not */
	bool child_of_caller = false;
	struct thread *t = thread_current();
	struct child_process *child;
	struct list_elem *e;
	for(e=list_begin(&t->child_list); e!=list_end(&t->child_list);
			e=list_next(e)){
		child = list_entry(e, struct child_process, cp_elem);
		if(child->pid == child_tid){
			child_of_caller = true;
			break;
		}
	}
	if(child_of_caller==false) return -1;

	/* 3. Check that it is invalid child_tid or not */
	if(child==NULL || child_tid<NO_PARENT)	// Invalid child_tid
		return -1;

	/* 4. Check that process_wait() has already been calld */
	if(child->wait==true)	// Already called!
		return -1;

	// In here, child_tid is neither invalid nor wait state
	child->wait=true;
	while(child->exit==false){
		barrier();
	}
	
	// In here, child_tid dies. Free child page and return exit_status.
	exit_status = child->exit_status;
	remove_child(child);
	return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

	remove_all_child();
	// If current thread has a parent, set child process exits.
	bool parent_exist = false;
	parent_exist = find_thread(cur->parent_tid);
	if(parent_exist==true)	cur->cp->exit = true;	//현재스레드는차일드고이제exit
	else										cur->cp->exit = false;
	// 열어놓은 파일들 닫기
	struct file_descriptor *file_descriptor=NULL;
	struct file *file;
	struct list_elem *e;
/*
   while (!list_empty (&list))
     {
       struct list_elem *e = list_pop_front (&list);
       ...do something with e...
     }
*/
   while (!list_empty (&cur->fd_list)){
		e = list_pop_front (&cur->fd_list);
		file_descriptor = list_entry(e, struct file_descriptor, fd_elem);
		file = file_descriptor->file;
		file_close(file);
		palloc_free_page(file_descriptor);	// open()에서 할당한 page 해제
	 }
	// load에서 file_deny_write()해놓은 것을 해제하고 파일 닫기
	file_close(cur->exec_file);	// file_close가 file_allow_write포함

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofset;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
	
	/* Parsing file_name and arguments. - KH */
	// type cast file_name.
	char **argv = (char **)palloc_get_page(PAL_USER);	// parsed arguments array
	int argc;			// arguments count
	// parse_fn returns parsed arguments array and arguments count
	argc = parse_fn(file_name, argv);	
	const char *parsed_file_name = argv[0];
	
  /* Open executable file. */
  file = filesys_open (parsed_file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", parsed_file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", parsed_file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofset = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofset < 0 || file_ofset > file_length (file))
        goto done;
      file_seek (file, file_ofset);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofset += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

	/* Store the passed arguments on the stack. - KH*/
	put_argument_on_stack(argv, argc, esp);

	/* Check result using hex_dump() kh*/
	/* Start of test code */
	//hex_dump((uintptr_t)PHYS_BASE-200, PHYS_BASE-200, 200, true);
	/* End of test code */

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
	// Denying writes to executables
	struct thread *exec_thread = thread_current();
	file_deny_write(file);
	exec_thread->exec_file = file;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);	// process_exit()으로 close시점을 미룬다.
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *knpage = palloc_get_page (PAL_USER);
      if (knpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, knpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (knpage);
          return false; 
        }
      memset (knpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, knpage, writable)) 
        {
          palloc_free_page (knpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *th = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (th->pagedir, upage) == NULL
          && pagedir_set_page (th->pagedir, upage, kpage, writable));
}


/*******************************************/
/************ User defined - KH ************/
/*******************************************/

/* Parse the filename and arguments */
int
parse_fn(const char *file_name, char **argv)
{
	int i;	// counter
	char *copy = (char *)palloc_get_page(PAL_USER);
	if(copy==NULL)
		thread_exit();
	strlcpy(copy, file_name, PGSIZE);

	char *token;
	char *save_ptr;
	i=0;
	for(token = strtok_r(copy, " ", &save_ptr); token;
			token=strtok_r(NULL, " ", &save_ptr))
	{
		argv[i] = (char *)palloc_get_page(PAL_USER);
		strlcpy(argv[i],token,strlen(token)+1);
		i++;
	}
	return i;
}

/* Tokenize the 'parse' with a deliminator " ",
	 each arguments will be saved into the 'esp'. */
void put_argument_on_stack(char **argv, int argc, void **esp)
{
	/* argv = file name and arguments
		 argc = argument count 
		 esp = &if_.esp */

	int i,j;
	// offset array which indicates each argument's distance from argv[0]
	int *argv_offset = palloc_get_page(PAL_USER);
	int offset_from_start=0;
	for(i=0; i<argc; i++){
		if(i==0) 
			argv_offset[i] = 0;
		else{
			argv_offset[i] = offset_from_start + (strlen(argv[i-1])+1);
			offset_from_start = argv_offset[i];
		}
	}

	/* copy arguments' character in reverse order from top of the stack
		 eg. '\0'x'\0'ohce    echo'\0'x'\0' */
	for(i=argc-1; i>=0; i--)
		for(j=strlen(argv[i]); j>=0; j--)	// start writing from null string('\0')
		{
			*esp = *esp - 1;	// stack grows down
			*(char *)(*esp) = argv[i][j];
		}

	int start_argv = (int)*esp;	// starting point of argv datas
	//ASSERT(false);
	/*		o
				h
				c
->*esp	e	// first byte of argv[0] (=='echo')
	*/

	/* The statement below makes alignment.
		 Since 32-bit singed int larger than 0x80000000 means negative integer,
		 we add 4 if *esp is negative integer. */
	*esp = ((int)(*esp)%4<0? *esp-((int)(*esp)%4+4) : *esp-(int)(*esp)%4);
	
	// argv[argc] means null pointer sentinel(pintos-p.36)
	*esp -= 4;
	*(int*)(*esp) = 0;

	// arguments' address
	for(i=argc-1; i>=0; i--)
	{
		*esp -= 4;
		//*(char*)(*esp) = start_argv + (uint32_t)argv_offset[i];
		*(char**)(*esp) = (char*)(start_argv + argv_offset[i]);
		//printf("start_argv + offset = %x\n", start_argv + argv_offset[i]);
	}
	//ASSERT(false);

	// starting address of argv(==argv[0]'s address)
	*esp -= 4;
	*(char ***)(*esp) = (*esp + 4);
	// store argc
	*esp -= 4;
	*(int *)(*esp) = argc;
	//return address(== 0)
	*esp -= 4;
	*(void **)(*esp) = (void *)0;

	//palloc_free_page((void *)argv_offset);
}

struct child_process *init_add_child(tid_t tid){
	// Page allocation for child_process
	struct child_process *child;
	child = (struct child_process *)palloc_get_page(PAL_USER);
	// Store informations.
	child->pid = tid;
	child->exit = false;
	child->load = NOT_LOADED;
	child->wait = false;
	struct thread *parent = thread_current();
	list_push_back(&parent->child_list, &child->cp_elem);
	lock_init(&child->cp_lock);
	return child;
}

struct child_process *get_child(tid_t tid){
	// If it founds child_process return that, otherwise return NULL pointer
	struct child_process *child;
	struct list_elem *e;
	struct thread *t = thread_current();
	for(e=list_begin(&t->child_list); e!=list_end(&t->child_list);
			e=list_next(e)){
		child = list_entry(e, struct child_process, cp_elem);
		if((tid_t)child->pid == tid)
			return child;
	}
	return NULL;	// Not a child of the calling process
}

void remove_child(struct child_process *child){
	// Remove cp_elem from child_list and free child_process page
	list_remove(&child->cp_elem);
	palloc_free_page((void *)child);
}

void remove_all_child(void){
	struct child_process *child;
	struct list_elem *e;
	struct thread *t = thread_current();
	for(e=list_begin(&t->child_list); e!=list_end(&t->child_list);
			e=list_next(e)){
		child = list_entry(e, struct child_process, cp_elem);
		remove_child(child);
	}
}
