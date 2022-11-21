#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"


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
sys_halt_handler(){
	power_off();
}

void
sys_exit_handler(int arg1){
	thread_current()->process_status = arg1;
	thread_exit();
}

void
sys_write_handler(int arg1, void *arg2, unsigned arg3){
	// file_write();
}

bool sys_create_handler(char *arg1, unsigned arg2){
	return filesys_create(arg1, arg2);
}

bool sys_remove_handler(char *arg1){
	return filesys_remove(arg1);
} 

int sys_open_handler(char *arg1){
	// arg1은 파일 이름이야
	// dir에서부터 시작해서 쭉쭉 내려와야?
	// struct file * f = filesys_open(arg1);
	// return f->pos;
}

// int sys_filesize_handler(int arg1){
// 	struct file * f = filesys_open(arg1);
// 	return f->inode->data.length;
// }

// int sys_read_handler(int arg1, void * arg2, unsigned arg3){
	
// }
/* The main system call interface */
void
syscall_handler (struct intr_frame *f) { 
	// TODO: Your implementation goes here.
	int syscall_n = f->R.rax;
	switch (syscall_n)
	{
	case SYS_HALT:
		sys_halt_handler();
		break;
	case SYS_EXIT:
		sys_exit_handler(f->R.rdi);
		break;
	case SYS_WRITE:
		printf("%s", f->R.rsi);
		break;
	case SYS_FORK:
		break;
	case SYS_CREATE:
		f->R.rax = sys_create_handler(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = sys_remove_handler(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = sys_open_handler(f->R.rdi);
		break;
	case SYS_FILESIZE:
		// f->R.rax = sys_filesize_handler(f->R.rdi);
		break;
	case SYS_READ:
		// f->R.rax = sys_read_handler(f->R.rdi, f->R.rsi, f->R.rdx);
	default:
		break;
	}
}
