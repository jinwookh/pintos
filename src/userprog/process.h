#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

#define NOT_LOADED 0
#define FINISH_LOAD 1
#define FAIL_LOAD -1

struct file_descriptor{
	int fd;										// fd number
	struct file *file;				// 어느 파일에 대한 descriptor인지 저장
	struct list_elem fd_elem;	// thread구조체 fd_list 리스트 멤버에 추가
};

typedef int pid_t;
struct child_process	// KH 
{
	pid_t pid;
	int exit_status;		/* exit()'s return value */
	bool wait;
	bool exit;
	int load;
	struct lock cp_lock;
	struct list_elem cp_elem;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/******** User defined - KH *********/
int parse_fn(const char *file_name, char **argv);
void put_argument_on_stack(char **argv, int argc, void **esp);

struct child_process *init_add_child(tid_t tid);
struct child_process *get_child(tid_t tid);
void remove_child(struct child_process *child);
void remove_all_child(void);
#endif /* userprog/process.h */
