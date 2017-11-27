#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Project 3 - Fixed point arithmetic */
#define LEN_FRACTION 14		// length of fractional bits is 14 in 17.14 format

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Project #3. Thread */
static struct list block_list;			// blocked thread가 담긴 리스트

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */
static int load_avg;						/* Used to calculate priority */
int f = 1<<LEN_FRACTION;					//power(LEN_FRACTION);

#ifndef USERPROG
/* Project #3 */
bool thread_prior_aging;
#endif

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
bool less_priority (const struct list_elem* elem1, const struct list_elem* elem2, void* aux);
bool less_priority2 (const struct list_elem* elem1, const struct list_elem* elem2, void* aux);
/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);	
  list_init (&block_list);

	/* Project #3 - load_avg */
	load_avg = 0;
  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive(우선권을 지닌) thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore start_idle;
  sema_init (&start_idle, 0);
  thread_create ("idle", PRI_MIN, idle, &start_idle);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&start_idle);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();
  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();

#ifndef USERPROG
	/* Project #3 - BSD_scheduler calculating priority */
	/* In each tick, recent_cpu is incremented by 1 for the running thread only
		0. recent_cpu = recent_cpu + 1 */
	t->recent_cpu = t->recent_cpu + 1*f;

	/* Below is executed in each 4 ticks
		1. priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)	*/
	if(timer_ticks() % 4 == 0){
		calc_priority();
	}

	/* Below is executed in each second(== 100 tick)
		2. load_avg = (59/60) * load_avg + (1/60) * ready_threads
		3. recent_cpu = (2*load_avg) / (2*load_avg + 1) * recent_cpu + nice */
	if(timer_ticks() % TIMER_FREQ == 0){
		if(thread_mlfqs==true){
			calc_load_avg();
			calc_recent_cpu_for_all();
		}// end of if(thread_mlfqs==true)
	}// end of if(timer_ticks() % TIMER_FREQ == 0)

	/* Project #3 - Alarm clock */
	thread_wake_up();

	/* Project #3 */
	//진욱- aging함수가 호출되는 간격을 10tick으로 늘렸다.
	//tick마다 thread_aging 이 작동되면 무언가가 충돌하는 것으로 보인다.
	if (thread_prior_aging == true && timer_ticks() % 10 == 0)
		thread_aging();
	//사소한 의문 하나: timer_ticks() 안에는 interrupt_enable 함수가 있고, 그 함수 안에는 external interrupt면 assertion을 발생하게 하는 코드가 있다.
	//근데 왜 이 코드에서 assertion이 발생하지 않는 것일까?
#endif
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);	// kf는 t->stack에서 kf size 내려온 위치
																		// alloc_frame()에서 t->stack 업데이트 됨
  kf->eip = NULL;										// return addr = NULL
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);	// ef는 t->stack에서 ef size 내려온 위치
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

	/* Store parent info and init&add child process - KH */
  t->parent_tid = thread_current()->tid;
#ifdef USERPROG
  struct child_process *child_process = init_add_child(t->tid);
  
  t->cp = child_process;
#endif
  /* Add to run queue. */
  thread_unblock (t);
  if(!thread_prior_aging) {
  //만약 aging test를 수행할 경우 thread_create될 때 preempt가 발생하지 않도록 한다. 
	  thread_yield();
  }
  return tid;
}	// end of thread_create()

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().
	 쓰레드를 언블락하기 전까지 현재 스레드를 재운다. 인터럽트 해제 후 호출!
   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)
	 러닝 스레드를 레디로 만드려면 thread_yield()사용
   This function does not preempt(선취하다) the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;
  //추가-진욱
  void* aux = NULL;
  list_less_func *priority_func = less_priority2;

  ASSERT (is_thread (t));	// is_thread는 스레드 구조체 침범했는지 검사

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
	/* Project 3 */
	/* If new_thread that will be unblocked has higher priority
			than current thread, current thread yield the processor immediately
		 If not, new_thread will be inserted in the ready list as priority order*/
  list_insert_ordered (&ready_list, &t->elem, priority_func, aux);
  t->status = THREAD_READY;
	intr_set_level (old_level);	// interrupt 다시 세팅
	//추가 - 진욱
//	thread_yield();//preemption하는 역할을 한다.
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());	// external interrupt를 처리중이 아니면 false리턴

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
	thread_current ()->status = THREAD_DYING;
	schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  void * aux = NULL;
  list_less_func* priority_func = less_priority2;
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 		// idle이면 이미 ready_list에 존재
    list_insert_ordered (&ready_list, &cur->elem, priority_func, aux);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);	// 인터럽트 off일때만 함수 수행

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
			/* e.next주소 -  thread구조체 시작에서 allelem.next까지 offset 
				= thread의 시작 주소로 변환
			*/
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  thread_current ()->priority = new_priority;
  thread_yield();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int new_nice) // 원래 (int nice UNUSED)로 되어있었음
{
	struct thread *t = thread_current();
	t->nice = new_nice;
	// priority를 새로 계산해서 업데이트 - 함수를 만들어서 호출
	calc_priority();
	// 우선순위에 따라 양보 - thread_yield()호출
	thread_yield();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
	int f = power(LEN_FRACTION);
	int result = (100*load_avg + f/2) / f;	// 가장 근처 정수로 반올림
	/* start of test code */
	//int result = (100*load_avg) / f;	// 가장 근처 정수로 반올림
	/* end of test code */
  return result;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
	int f = power(LEN_FRACTION);
	int recent_cpu = thread_current()->recent_cpu;
	int result = (100*recent_cpu + f/2) / f;	// 가장 근처 정수로 반올림
	/* start of test code */
	//int result = (100*recent_cpu) / f;	// 가장 근처 정수로 반올림
	/* end of test code */
  return result;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
	ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
	/* Just only parsing program name. Since later in load() parse_fn called */
#ifdef USERPROG
  	size_t i;
	char prog_name[30];
	strlcpy(prog_name, name, sizeof prog_name);
	for(i=0;i<strlen(prog_name);i++){
		if(prog_name[i]==' '){
			prog_name[i]='\0';
			break;
		}
	}
  strlcpy (t->name, (const char *)prog_name, sizeof t->name);
#endif
#ifndef USERPROG
  strlcpy (t->name, name, sizeof t->name);
#endif
	/* Project #3 */
	///* 상속 구현을 위해 주석 처리
	t->recent_cpu = 0;
	t->nice = 0;
	//*/

  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;	// is_thread()에서 확인할 부분(이게 바뀌면 안됨)
  list_push_back (&all_list, &t->allelem);
/* start of test code */
//#ifndef USERPROG
/* end of test code */
#ifdef USERPROG	// origin code
	// Initialize for child process - KH
	if(strcmp(name, "main")==0){	// Case : main thread - NO_PARENT
		t->parent_tid = NO_PARENT;
		// start of test code
		t->recent_cpu = 0;
		t->nice = 0;
		/* end of test code */
	}
	else{													// Case : Others must have parent thread
		t->parent_tid = thread_current()->tid;
		/* start of test code */
			t->recent_cpu = thread_current()->recent_cpu;
			t->nice = thread_current()->nice;
		/* end of test code */
	}
	list_init(&t->child_list);		// Initializing child_list
	list_init(&t->fd_list);				// Initializing fd_list
	t->cp = NULL;
#endif

}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);
	/* thread t->stack은 init시 t에 PGSIZE를 더해 t+4kB에 위치
		 t->stack에서 프레임의 사이즈 만큼을 빼주어 base address를 확보한다.	*/
  t->stack -= size;	  
	return t->stack;

}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice, that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;	// static이니까 함수빠져나가도 값 유지
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
// thread구조체 시작지점에서 stack멤버까지의 오프셋을 미리 계산 해놓음

// 스레드의 존재 여부를 리턴
bool
find_thread(tid_t tid)
{
	struct thread *find;	// Finder for finding thread which has tid
	struct list_elem *e;
	for(e=list_begin(&all_list); e!=list_end(&all_list); e=list_next(e)){
		find = list_entry(e, struct thread, allelem);
		// Update current thread's exit_status
		if(tid == find->tid) return true;
	}
	return false;
}

// 스레드의 존재 여부를 확인 하고 스레드를 리턴
struct thread*
return_thread(tid_t tid)
{
	struct thread *find;	// Finder for finding thread which has tid
	struct list_elem *e;
	for(e=list_begin(&all_list); e!=list_end(&all_list); e=list_next(e)){
		find = list_entry(e, struct thread, allelem);
		// Update current thread's exit_status
		if(tid == find->tid) return find;
	}
	return NULL;
}

bool
is_user_vaddr_in_process(tid_t tid)
{	
	struct list_elem *e;
	struct thread *t = NULL;
	for(e=list_begin(&all_list); e!=list_end(&all_list); e=list_next(e)){
		t = list_entry(e, struct thread, allelem);
		if(t->tid==tid)
			break;
	}
	if(!is_user_vaddr(t)) return false;
	else									return true;
}

/* Prj 3 */
void
thread_wake_up(void)
{
	/* Iterate block queue and find threads which wake up
		 <Preparations>
		 1. block queue : block_list
		 2. list element : struct list_elem *e		cf) src/lib/kernel/list.h
	*/
	struct list_elem *e;
	struct thread *t;
	int64_t wakeup_time;

	for(e=list_begin(&block_list); e!=list_end(&block_list); e=list_next(e)){
		t = list_entry(e, struct thread, block_elem);
		wakeup_time = t->wakeup_time;
		if(timer_ticks() >= wakeup_time){
			list_remove(e);			//delete from block_list
			thread_unblock(t);
		}
	}
}

void
thread_aging(void)
{
/*for문을 돌면서 reqdy qeuue안의 thread priority를 1씩 올려준다.
  그러고 나서 thread_yield를 호출해서 preempt가 발생하게 한다.*/
 struct list_elem* e;
 struct thread *t;

 void* aux = NULL;
 list_less_func *priority_func = less_priority2;

 for (e =  list_begin(&ready_list); e!= list_end(&ready_list); e = list_next(e)) {
	 t = list_entry(e, struct thread, elem);
	 t->priority += 1;
	 list_sort ( &ready_list, priority_func, aux);
 }


//priority_aging ready queue 상태를 알아보기 위한 실험.////////
/*printf("ready_queue: ");	
for (e=list_begin (&ready_list); e!=list_end (&ready_list); e=list_next (e)){
	t = list_entry(e, struct thread, elem);
	msg("%s ", t->name);
	}
printf("end!\n");
*/


 /* external interrupt handler가 작동중일 때는 thread_yield를 사용할 수 없으므로(assertion에 걸린다.),
    그와 동일한 동작을 하는 intr_yield_on_return() 함수를 사용한다.
    external interrupt와 intr_yield_on_return()에 관한 자세한 함수는 pintos 문서 A.4.3를 참조하세요.
    */
	intr_yield_on_return(); 


}

void push_to_block_list (struct list_elem *elem)
{
	void* aux = NULL;
	list_less_func *priority_func = less_priority;
	//정렬을 도와주는 함수에 대한 함수 포인터
	list_insert_ordered(&block_list, elem, priority_func, aux);
	
	//정렬을 유지하면서 삽입을 한다.
}

/* Used for f = 2^q in fixed point arithmetic */
int power(int exp){
	int result = 1;
	int i;
	for(i=0; i<exp; i++)
		result = result * 2;
	return result;
}

bool less_priority ( const struct list_elem *elem1, 
										 const struct list_elem *elem2, 
										 void* aux UNUSED) {	
	/* UNUSED매크로를 사용하면 컴파일러가 함수 내부에서
	   해당 파라미터가 사용되지 않았어도 warning메시지를
		 만들지 않은 채로 무시하고 지나감*/
	struct thread * newone;
	struct thread * oldone;
	
	newone = list_entry(elem1, struct thread, block_elem);
	oldone = list_entry(elem2, struct thread, block_elem);
	//list_entry를 사용할 때는 구조체의 어떤 부분이 list_elem인지 꼭 
//	확인하자.
//newone은  ready queue에 새로 들어오는 쓰레드
//oldone은 ready queue에 원래  있던 쓰레드 - newone의 비교 대상
//내림차순으로 정렬해야 pop_front했을 때 가장 큰 priority를 갖는 thread가 실행된다.
	if (newone->priority > oldone->priority){
		return true;
	}//true 라면 loop를 빠져나와 oldone 쓰레드의 옆에 위치한다.
//1, 2, 4. 5라는 기존 리스트에 3을 대입하고자 한다면
// 4옆에서 3이 비교를 멈추는 것과 같은 원리이다.
	else {
		return false;
	}
}

//ready queue에서 priority순 정렬을 하기 위한 코드
bool less_priority2 ( const struct list_elem *elem1, 
											const struct list_elem *elem2, 
											void* aux UNUSED) {
	struct thread * newone;
	struct thread * oldone;
	
	newone = list_entry(elem1, struct thread, elem);
	oldone = list_entry(elem2, struct thread, elem);
	//list_entry를 사용할 때는 구조체의 어떤 부분이 list_elem인지 꼭 
//	확인하자.
//newone은  ready queue에 새로 들어오는 쓰레드
//oldone은 ready queue에 원래  있던 쓰레드 - newone의 비교 대상
//내림차순으로 정렬해야 pop_front했을 때 가장 큰 priority를 갖는 thread가 실행된다.
	if (newone->priority > oldone->priority){
		return true;
	}//true 라면 loop를 빠져나와 oldone 쓰레드의 옆에 위치한다.
//1, 2, 4. 5라는 기존 리스트에 3을 대입하고자 한다면
// 4옆에서 3이 비교를 멈추는 것과 같은 원리이다.
	else {
		return false;
	}
}

/* 함수이름 : calc_load_avg
   하는  일 : 아래와 같음
1-1. Calculating ready_threads
	ready_threads is the number of threads that are either running or 
		ready to run at time of update(not including the idle thread)
1-2. Calculating load_avg using Fixed point arithmetic
	 Formula : load_avg = (59/60) * load_avg + (1/60) * ready_threads
	 load_avg is real number, ready_threads is integer
	 but we already defined type of load_avg to integer.
	 Thus there is no need to convert load_avg to fixed point
		 (represented in integer).
	 But 59/60 and 1/60 is real number so we must convert them to use.
	 Otherwise, 59/60 = 0 and 1/60 = 0. If so, load_avg is always to be 0.
	 To convert them to fixed point value, multiply dividend by f=2^14.
	 Thus 59/60 and 1/60 are converted to 59*f/60 and 1*f/60, respectively.

	 Multiplying two fixed-point value formula is 
				((int64_t)x) * y /f where x and y = real_number * f
	 Beacuse of possibility of overflow, one of fixed-point is casted
	 to int64_t. And to let the result to be fixed-point,	only one division
	 is used.
	 -> ( (int64_t)(59*f/60) ) * load_avg / f where f is 2^14
	 since load_avg is already converted to fixed point, not using load_avg*f
*/
void
calc_load_avg(void){
	struct thread *t = thread_current();
	struct list_elem *e;
	if(t!=idle_thread)	// idle 제외하고 매 틱마다 1증가
		t->recent_cpu = t->recent_cpu + 1*f;	// Fixed point + integer
	/* start of test code */
	//t->recent_cpu = t->recent_cpu + 1*f;	// Fixed point + integer
	/* end of test code */

	int ready_threads = 0;
	// Number of running & ready threads excluding idle thread
	// 1) count running thread
	if (t != idle_thread)	
		ready_threads = ready_threads + 1; // +1 for running
	// 2) count ready thread
	for (e=list_begin (&ready_list); e!=list_end (&ready_list); 
			 e=list_next (e)){
		t = list_entry(e, struct thread, elem);
		if(t != idle_thread)
			ready_threads = ready_threads + 1;
	}
	load_avg = ((int64_t)(59*f/60))*load_avg/f + (1*f/60)*ready_threads;
}

/* 함수이름 : calc_recent_cpu
   하는  일 : 인자로 받은 스레드에 대하여 recent_cpu 재계산
 2. Calculating recent_cpu using Fixed point arithmetic
	 1)Original Formula
	 	 recent_cpu = (2*load_avg) / (2*load_avg + 1) * recent_cpu + nice
	 2)Formula represented in Fixed point arithmetic
		 recent_cpu = (((int64_t) 2*load_avg) * f / (2*load_avg + 1*f))
					* recent_cpu / f + nice*f 
*/
void
calc_recent_cpu(struct thread *t){
	int nice = t->nice;
	int recent_cpu = ( ((int64_t) 2*load_avg)*f/(2*load_avg + 1*f) ) 
									* t->recent_cpu / f + nice*f;
	t->recent_cpu = recent_cpu;
}
/* 함수이름 : calc_recent_cpu_for_all
   하는  일 : 1초(100틱)마다 존재하는 모든 스레드에 대하여 recent_cpu 재계산
*/
void
calc_recent_cpu_for_all(void){
	// Iterate all_list and calculate each thread's recent_cpu
	struct thread *t;
	struct list_elem *e;
	for(e=list_begin(&all_list); e!=list_end(&all_list);
			e=list_next(&all_list)){
		t = list_entry(e, struct thread, allelem);
		calc_recent_cpu(t);
	}
}
/*2.2.4 BSD scheduler - Calculating priority
파라미터: nice 
하는  일: 공식에 따라 새로운 priority를 계산하여 스레드에 업데이트함.
	1) Formula
				priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)
	2) Formula represented in Fixed point arithmetic
				priority = PRI_MAX - (recent_cpu/f/4) - (nice * 2)
	Since recent_cpu is Fixed point number, if we want to convert it to
		real number, it needs to be divided by f.
	The others has no needs of consideration.
*/
void
calc_priority(void){
	//int f = power(LEN_FRACTION);		// Value of 14 - defined in this file
	struct thread *t = thread_current();
	int nice = t->nice;
	int recent_cpu = t->recent_cpu;
	t->priority = PRI_MAX - (recent_cpu/f/4) - (nice * 2);
}
#include "threads/thread.h"
