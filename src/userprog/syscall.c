#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"	
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"		// for halt()
#include "devices/input.h"			// for read()
#include "lib/kernel/console.h"	// for write()

/* for project 2-2 */
#include "filesys/filesys.h"	
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/palloc.h"

#define USER_VADDR_START ((void *)0x08048000)
#define NO_PARENT -1
/*  struct file _ descriptor 정의 process.h로 옮김 */
struct lock syscall_lock;
static void syscall_handler (struct intr_frame *);
void sum(int num1, int num2, int num3, int num4);
int take_kernel_vaddr(void *uaddr);
void get_args (struct intr_frame *f, int *argv, int argc);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void check_valid_addr(void *esp);

/* for project 2-2 */
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
struct file* find_file(int fd);
struct file_descriptor* find_file_descriptor(int fd);

void
syscall_init (void) 
{
	lock_init(&syscall_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	/*
	<핸들러가 호출되는 흐름 및 핸들러가 하는 일>
	유저 프로그램에서 시스템 콜을 호출하면 lib/user/syscall.c의 시스템 콜
	함수가 호출된다. 매크로는 0x30 인터럽트를 발생시키고
	인터럽트 벡터 테이블을 참조하여 시스템 콜 핸들러를 호출한다.
	핸들러에서 실제 구현해야할 시스템 콜을 호출한다.

		<핸들러에서 실제 해야할 일>
		핸들러에 오기 전에 이미 유저 스택에는 arg들이 쌓여있다.
		lib/user/syscall.c에 정의된 시스템 콜 함수들이 그 파일에 있는 매크로를
		이용하여 유저 스택에 arg들을 쌓아둔 것이다.
		따라서 핸들러 함수에서는 유저 스택에 쌓인 arg들을 가져온다. 
		f->esp로 가장 먼저 접근 가능한 것은 syscall number이다. 
		syscall-nr.h가 인클루드 되어 있기에 구분가능하다.
		그다음 4바이트씩 올라오면서(증가하면서) arg0, arg1을 읽을 수 있다.
		(스택에 쌓을 때 4바이트씩 내리면서 쌓기 때문)
		또한 읽어온 arg0, arg1, arg2등은 실제 값이 아니라 주소값을 가지고 있다.
		따라서 4바이트 주소값에 접근하여 실제 알맞은 타입으로 캐스팅해서
		실제 값을 사용해야 한다. 각 시스템 콜 함수의 파라미터 타입에 맞춘다.
		이 핸들러 함수에서는 각 케이스에 대해서 구별해주고 함수 호출까지 해준다.
		이 함수를 벗어난 곳에서 exit, wait등의 각 시스템 콜 함수를 구현한다.
	*/
	// Maximum # of arguments == 4 (Change this 3 to 4 for added syscall)
	int argv[4];	
	void *ptr = f->esp;	// address of system call #
	// Check stack pointer's validity
	check_valid_addr(ptr);
	switch (*(int *)ptr){
		case SYS_HALT:{		// #0
			halt();
			break;
		}
		case SYS_EXIT:{		// #1
			get_args(f, argv, 1);
			exit(argv[0]);
			break;
		}
		case SYS_EXEC:{		// #2
			get_args(f, argv, 1);
			argv[0] = take_kernel_vaddr((void *)argv[0]);
			f->eax = (uint32_t)exec((const char *)argv[0]);
			break;
		}
		case SYS_WAIT:{		// #3
			get_args(f, argv, 1);
			f->eax = (uint32_t)wait((pid_t)argv[0]);
			break;
		}
		case SYS_CREATE:{		// #4
			get_args(f, argv, 2);
			f->eax = (uint32_t)create((const char *)argv[0], (unsigned)argv[1]);
			break;
		}
		case SYS_REMOVE:{		// #5
			get_args(f, argv, 1);
			f->eax = (uint32_t)remove((const char *)argv[0]);
			break;
		}
		case SYS_OPEN:{			// #6
			get_args(f, argv, 1);
			f->eax = (uint32_t)open((const char *)argv[0]);
			break;
		}
		case SYS_FILESIZE:{	// #7
			get_args(f, argv, 1);
			f->eax = (uint32_t)filesize(argv[0]);
			break;
		}
		case SYS_READ:{		// #8
			get_args(f, argv, 3);
		//f->eax = read (int fd, void *buffer, unsigned size);
			f->eax = read (argv[0], (void *)argv[1], (unsigned)argv[2]);
			break;
		}
		case SYS_WRITE:{	// #9
			get_args(f, argv, 3);
		//f->eax = write (int fd, const void *buffer, unsigned size);
			f->eax = write (argv[0], (const void *)argv[1], (unsigned)argv[2]);
			break;
		}
		case SYS_SEEK:{		// #10
			get_args(f, argv, 2);
			//seek(argv[0], (unsigned)argv[1]);	// Return type is void
			break;
		}
		case SYS_TELL:{		// #11
			get_args(f, argv, 1);
			//f->eax = (uint32_t)tell(argv[0]);
			break;
		}
		case SYS_CLOSE:{	// #12
			get_args(f, argv, 1);
			//close(argv[0]);	// Return type is void
			break;
		}
		case SYS_PIBONACCI:{	// #13 - project userprog 2-1
			get_args(f, argv, 1);
			f->eax = pibonacci(argv[0]);
			break;
		}
		case SYS_SUM_OF_FOUR_INTEGERS:{	// #14 - project userprog 2-1
			get_args(f, argv, 4);
			f->eax = sum_of_four_integers(argv[0], argv[1], argv[2], argv[3]);
			break;
		}
	}// end_of_switch
}

/* Given basic system calls */
/* Refer to pintos document [3.3.4 System Calls] pdf-35 */
/* System call #0 : SYS_HALT */
void
halt (void){
	shutdown_power_off();
}

/* System call #1 : SYS_EXIT */
void
exit (int status){
	/* What exit() does : Return status to the kernel and terminates
		 user program. If its parent wait() for it, return status to parent. */
	bool find_parent;
	struct thread *t = thread_current();
	tid_t tid = t->parent_tid;	// Take parent tid.
	ASSERT(!(tid<NO_PARENT));			// Since tid starts from 1, it's not valid

	if(tid==NO_PARENT) find_parent=false;	// It doesn't have parent 
	else{	// It has parent
		/* Check that current thread has parent or not. */
		find_parent =	find_thread(tid);
		if(find_parent==false){
			ASSERT(true); // ERROR: Child must have its parent
		}
		else{														// Current thread is child process
			t->cp->exit_status = status;	// Update child's exit_status
		}
	}
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

/* System call #2 : SYS_EXEC */
pid_t
exec (const char *cmd_line){

/* code for denying writes to executables */
	// file이름만 따로 파싱 - exec-arg테스트 케이스에 필요
	char *file_name = (char *)palloc_get_page(PAL_USER);
	int i;
	for(i=0; ;i++){
		if(cmd_line[i]==' '){file_name[i]='\0'; break;}
		file_name[i] = cmd_line[i];
	}
/* end of code */

	// 1. Check pid's validity
	pid_t pid = (pid_t)process_execute(cmd_line);	// get new process id
	
/* start of code for denying writes to excutables */
	palloc_free_page((void *)file_name);
/* end of code */

	if(pid<0){ 
		return -1;	// Non-valid pid if pid < 0
	}
	/* 2. Check load()'s status. (load() is in process.c 
		 	  and called by start_process) */
	struct child_process* child = get_child(pid);	// get child of current_thread
	if(child==NULL){
		return -1; // Non-valid pid since it's not  child_process
	}
		// To prevent compiler from deleting while loop, use barrier().
	while(child->load == NOT_LOADED)	barrier();	// wait if not yet loaded

	// Result of load() for new process is success(FINISH_LOAD).
	if(child->load == FINISH_LOAD){
		return pid;
	}
	else{ 
		return -1;	// child->load == FAIL_LOAD
	}
}

/* System call #3 : SYS_WAIT */
int
wait (pid_t pid){
	return process_wait(pid);	// hand it over to process_wait
}

/* System call #4 : SYS_CREATE */
bool
create (const char *file, unsigned initial_size){
	bool result;
	if(file==NULL) exit(-1);	// Prevention for NULL pointer filename
	// Prevention for bad pointer
	//take_kernel_vaddr((void *)file);
	if(pagedir_get_page(thread_current()->pagedir, (void *)file)==NULL) exit(-1);
	lock_acquire(&syscall_lock);		// lock 걸기
	result = filesys_create(file, (off_t)initial_size);
	lock_release(&syscall_lock);		// lock 풀기
  return result;
}

/* System call #5 : SYS_REMOVE */
bool
remove (const char *file){
	/*
	1. filesys_open으로 file을 가져온다.
	2. file->deny_write를 확인하여 true 면 remove하지 않는다.
																 false면 remove한다.
	3. file_close로 file을 닫는다.
	4. remove결과를 리턴한다.
	*/
	bool result=false;
	lock_acquire(&syscall_lock);		// lock 걸기
	struct file *remove_file = filesys_open(file);
	lock_release(&syscall_lock);		// lock 풀기
	if(!remove_file->deny_write){	// Removing file
		lock_acquire(&syscall_lock);		// lock 걸기
		filesys_remove(file);
		lock_release(&syscall_lock);		// lock 풀기
		result = true;
	}
	file_close(remove_file);
	return result;
}

/* System call #6 : SYS_OPEN */
int
open (const char *file){
  /* 1. Return nonnegative integer handle called a "file descriptor".
		 		If the file could not be opened, return -1.
		 1. Each  process has an independent set of file descriptors.
		 		File descriptors are not inherited by child processes.
		 1. Every time open() is called for a single file,
		 	  each open returns a new file descriptor.
		 1. Different file descriptors for a single file are closed independently
		 	  in separate calls to 'close()' and they do not share a file position.
		 fd는 2부터 시작해서 계속 1씩 증가하게 만들었다.
	*/
	// 0. Setting variables.
	static int fd = 3;	// Starts from 2. Since 0, 1, 2 are reserved.
	struct file_descriptor *file_descriptor = palloc_get_page(0);

	// Prevention for bad pointer
	if(pagedir_get_page(thread_current()->pagedir, (void *)file)==NULL) exit(-1);

	// 1. Open the file
	lock_acquire(&syscall_lock);		// lock 걸기
	struct file *open_file = filesys_open(file);
	if(open_file==NULL){
		palloc_free_page(file_descriptor);
		lock_release(&syscall_lock);
		return -1;
	}

	// 2. Take current thread and Store fd information.
	struct thread *thread = thread_current();
	file_descriptor->fd = fd;
	file_descriptor->file = open_file;
	list_push_back(&thread->fd_list, &file_descriptor->fd_elem);

	// 3. Increments fd and Return fd
	lock_release(&syscall_lock);		// lock 풀기
	return fd++;
}

/* System call #7 : SYS_FILESIZE */
int
filesize (int fd){
	/* Returns the size, in bytes, of the file open as fd. */
	off_t size;
	/* fd를 이용해서 struct file 가져오기 */
	lock_acquire(&syscall_lock);		// lock 걸기
	struct file *file =	find_file(fd);
	if(file==NULL){
		lock_release(&syscall_lock);		// lock 풀기
		return -1;		// fd로 파일을 못찾은 경우 -1을 리턴
	}
	// Open the file using file_descriptor
	size = file_length(file);
	lock_release(&syscall_lock);		// lock 풀기
	return (int)size;
}

/* System call #8 : SYS_READ */
int
read (int fd, void *buffer, unsigned size){
/* Read character from keyboard, store it into buffer.
	 Return the number of bytes actually read */
	char c;
	int count;	// Counter for number of bytes actually read
	if(fd==0){	// fd==0 means STDIN!
		for(count=0; count<(int)size; count++){
			c = input_getc();			// Read character from keyboard(devices/input.c)
			*(char *)buffer = c;	// Store it into buffer
			count++;							// Update counter
			if(c=='\0') break;		// Read until EOF
		}// end of while(1)
		return count;
	}// end of if(fd==0)
	else{
/* Reads size bytes from the file open as fd into buffer.
	 Returns the number of bytes actually read (0 at end of file),
	 	or -1 if the file could not be read
*/
		lock_acquire(&syscall_lock);		// lock 걸기
		struct file *file = find_file(fd);
		// Prevention for bad pointer about buffer
		check_valid_addr(buffer);		// Prevent accessing kernel
		if(pagedir_get_page(thread_current()->pagedir,buffer)==NULL)
			exit(-1);

		if(file==NULL){
			lock_release(&syscall_lock);
			return -1;	// fd로 파일을 못찾은 경우
		}
		count = file_read(file, buffer, size);
		lock_release(&syscall_lock);		// lock 풀기
		return count;
	}
}// end of read() function

/* System call #9 : SYS_WRITE */
int
write (int fd, const void *buffer, unsigned size){
/* Write character to console, which is read from buffer.
	 Return the number of bytes actually written */
	int count;	// Counter for number of bytes actually write
	if(fd==1){	// STDOUT
		putbuf((const char *)buffer, (size_t)size);	// Write character to console
		return (int)size;
	}// end of if(fd==1)
	else{
/* Writes size bytes from buffer to the open file fd.
	 Returns the number of bytes atually written,
	 which may be less than size if some bytes could not be written.
*/
		lock_acquire(&syscall_lock);		// lock 걸기
		struct file *file = find_file(fd);
		// Prevention for bad pointer about buffer
		void *buf = (void *)buffer;
		check_valid_addr(buf);		// Prevent accessing kernel
		if(pagedir_get_page(thread_current()->pagedir,buffer)==NULL)
			exit(-1);

		if(file==NULL){
			lock_release(&syscall_lock);
			return -1;	// fd로 파일을 못찾은 경우
		}
		count = file_write(file, buffer, size);
		lock_release(&syscall_lock);		// lock 풀기
		return count;
	}
}// end of write() function


/* System call #10 : SYS_SEEK */
void
seek (int fd, unsigned position) {
	lock_acquire(&syscall_lock);		// lock 걸기
	struct thread *t = thread_current();
	struct list_elem *e;
	bool foundFile = false;
	struct file_descriptor *f;
	/* 개요: current thread의 fd_list 안의 파일들을 검사하여
		일치하는 fd를 가진 파일이 있으면,
		file의 position을 new position으로 옮긴다.
	*/
	 
	 /*if(position < 0) {
		 return ;
	 }position은 항상 0보다 크거나 같으므로 필요가 없는 코드*/
		for(e = list_begin(&t->fd_list); e != list_end(&t->fd_list); 
				e = list_next(e)) {
			f = list_entry(e, struct file_descriptor, fd_elem);
			if(f->fd == fd) {
				foundFile = true;
				//file의 커서를 변경하는 작업을 하므로 앞뒤로 lock을 걸고 풀어준다.
				file_seek(f->file, (off_t)position);
				lock_release(&syscall_lock);		// lock 풀기
				break;
			}
		}
		lock_release(&syscall_lock);		// lock 풀기
		/*위 루프에서 알맞은 fd를 못 찾으면 패닉을 일으키게 하는 방법도
		그런 방법을 쓰지 않았음.*/
		//pintos 문서의 내용(앞으로 해야 하는 일과 관련될 수도....
		/*A later read obtains 0 bytes, indicating end of file.
		A later write extends the file, filling any unwritten gap zeros
		(However, in Pintos files have a fixed length until project 4 is complete,
		so writes past end of file will return an error.)*/
}

/* System call #11 : SYS_TELL */
unsigned
tell (int fd){
	lock_acquire(&syscall_lock);		// lock 걸기
	struct thread *t = thread_current();
	struct list_elem *e;
	unsigned position = 0;
	struct file_descriptor *f;
	/* 개요: current thread의 fd_list에서 찾고자 하는 fd를 찾은 후
					list_entry를 사용하여 파일에 대한 정보까지 알아낸다.
					그 후 파일을 참조하여 파일 커서의 위치를 리턴한다.*/ 
	for(e = list_begin(&t->fd_list); e != list_end(&t->fd_list);
			e = list_next(e)) {
		f = list_entry(e, struct file_descriptor, fd_elem);
		if(f->fd ==  fd) {
			position = file_tell(f->file);
			lock_release(&syscall_lock);		// lock 풀기
			break;
		}
	}
	lock_release(&syscall_lock);		// lock 풀기
	return position;
}

/* System call #12 : SYS_CLOSE */
void
close (int fd){
	lock_acquire(&syscall_lock);		// lock 걸기
	struct file *file = find_file(fd);
	if(file==NULL){
		lock_release(&syscall_lock);	// lock풀기
		return;
	}
	file_close(file);
	// file_descriptor를 fd_list에서 지운다.
	// file_descriptor를 찾아서 page 할당 해제.
	struct file_descriptor *file_descriptor = find_file_descriptor(fd);
	list_remove(&file_descriptor->fd_elem);
	palloc_free_page(file_descriptor);
	lock_release(&syscall_lock);		// lock 풀기
}

/* Check stack pointer whether it points user area or not
	 User virtual address : 0x08048000<=  esp  <PHYS_BASE 	*/
void
check_valid_addr(void *esp)
{
	if(esp >= PHYS_BASE || esp < USER_VADDR_START){
		exit(-1);
	}
}

int
take_kernel_vaddr(void *uaddr){
	check_valid_addr(uaddr);	// Check for validity.
	void *kernel_vaddr = pagedir_get_page(thread_current()->pagedir, uaddr);
	// uaddr -> finding physical addr in pagedir -> + PHYS_BASE = kernel_vaddr
	if(kernel_vaddr == NULL)
		exit(-1);
	return (int)kernel_vaddr;
}

/* Bring arguments using f->esp
	 argc = # of arguments */
void
get_args (struct intr_frame *f, int *argv, int argc){
	// Since f->esp means syscall #, argv[0] starts from (int *)f->esp + 1
	int i;
	int *ptr;
	/* added 171018_0417 */
	ptr = (int *)f->esp;
	// 아래는 중복 코드이다. 시스템 콜 핸들러를 들어와서 제일 먼저 체크했음.
	check_valid_addr((void *)ptr);	// Check validity for f->esp(sc-bad-arg.c)
	/* end of added */
	for(i=0; i<argc; i++){
		ptr = ptr + 1;
		//ptr = (int *)f->esp + 1 + i;
		check_valid_addr((void *)ptr);
		argv[i] = *ptr;
	}
}

/* Added system calls' implement - Project #2 */
int pibonacci(int n){
	int temp, i;
	int fn1 = 1;	// 1st fibonacci number
	int fn2 = 1;	// 2nd fibonacci number
	int fn = 0;				// Store Nth fibonacci number

	if(n<1){
		printf("Non-valid number\n");
		return 0;	// non-valid number
		//return -1;
	}

	if(n<3){
		printf("1 ");
		return 0; // 1st and 2nd number is 1
		//return 1;
	}

	for(i=0; i<n-2; i++){
		fn = fn1 + fn2;
		temp = fn2;
		fn2 = fn;
		fn1 = temp;
	}
	printf("%d ", fn);
	return 0;
}
int sum_of_four_integers (int a, int b, int c, int d){
	int sum = a+b+c+d;
	printf("%d\n", sum);
	return 0;
}

struct file*
find_file(int fd){
	struct list_elem *e;
	struct file_descriptor *file_descriptor=NULL;
	struct thread *thread = thread_current();
	bool find_fd = false;
	for(e=list_begin(&thread->fd_list); e!=list_end(&thread->fd_list);
			e=list_next(e)){
		file_descriptor = list_entry(e, struct file_descriptor, fd_elem);
		if(file_descriptor->fd == fd){ find_fd = true; break; }
	}
	// fd로 파일을 못찾는 경우 NULL을 리턴한다.(핀토스 문서에는 없음)
	if(find_fd==false) return NULL;
	return file_descriptor->file;
}

struct file_descriptor*
find_file_descriptor(int fd){
	struct list_elem *e;
	struct file_descriptor *file_descriptor=NULL;
	struct thread *thread = thread_current();
	bool find_fd = false;
	for(e=list_begin(&thread->fd_list); e!=list_end(&thread->fd_list);
			e=list_next(e)){
		file_descriptor = list_entry(e, struct file_descriptor, fd_elem);
		if(file_descriptor->fd == fd){ find_fd = true; break; }
	}
	// fd로 파일을 못찾는 경우 NULL을 리턴한다.(핀토스 문서에는 없음)
	if(find_fd==false) return NULL;
	return file_descriptor;
}
