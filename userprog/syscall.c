#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}


void
exit_handler (int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status); 
	thread_exit ();
}

void 
halt_handler (){
	power_off();
}

/* create : 파일을 생성하는 시스템 콜 (file, initial_size) */
bool create_handler(const char * file, unsigned initial_size){
	// if(*file == NULL){
	// 	exit(1);
	// }
	check_address(file);
	return filesys_create(file, initial_size);
}    


void check_address(void *addr){
	struct thread *curr = thread_current();
	/* 유저 메모리 주소에 있는지, 물리 메모리에 맵핑이 된 주소인지 확인 */


	if(!is_user_vaddr(addr) || pml4_get_page(curr->pml4, addr) == NULL && addr == NULL)
		exit(-1);
}

void get_argument(void *rsp, int **arg, int count){
	rsp = (int64_t *)rsp + 2;
	for (int i = 0; i < count; i++){
		arg[i] = rsp;
		rsp = (int64_t *)rsp + 1;
	}
}

void exit (int status){
	struct thread* cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}


/* The main system call interface */
/* 시스템 콜이 레지스터 rax에 저장한 시스템 콜 넘버에 따라 각기 다른 작업을 수행한다. */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// TODO: Your implementation goes here.

	/* rax : 시스템 콜 번호 */
	int syscall_no = f->R.rax;  

	/* 인자 전달 순서 */
	// uint64_t rdi = f->R.rdi;			
	// uint64_t rsi = f->R.rsi;	
	// uint64_t rdx = f->R.rdx;
	// uint64_t r10 = f->R.r10;
	// uint64_t r8 = f->R.r8;
	// uint64_t r9 = f->R.r9;	

	switch (syscall_no) {		// rax is the system call number

		/* SYS_HALT : pintos 종료 */
		case SYS_HALT : 
			halt_handler();
		break;

		/* SYS_EXIT : */
		case SYS_EXIT : 
			exit(f->R.rdi);
		break;
			
		// case SYS_FORK :
		// a3 = fork_handler(a3, f);
		// break;

		// case SYS_EXEC :
		// 	if (exec_handler (a1) == -1)
		// 	{
		// 		exit(-1);
		// 	}
		// break;

		// case SYS_WAIT :
		// break;

		case SYS_CREATE :
			f -> R.rax = create_handler(f->R.rdi, f->R.rsi);
		break;

		// case SYS_REMOVE :
		// break;

		// case SYS_OPEN :
		// break;

		// case SYS_FILESIZE :
		// break;

		// case SYS_READ :
		// break;

		case SYS_WRITE :
		printf("%s", (char*)f->R.rsi);
		break;

		// case SYS_SEEK :
		// break;

		// case SYS_TELL :
		// break;

		// case SYS_CLOSE :
		// break;

	}
}
