#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"

#include "threads/synch.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "kernel/stdio.h"
#include "filesys/file.h"
#include "user/syscall.h"
//#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// struct lock {
// 	struct thread *holder;
// 	struct semaphore semaphore;
// };

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
	lock_init(&filesys_lock);
}


/* RPOJECT2 : SYSTEMCALL EXTRA FUCNTION */
void
remove_file_from_fd_table(int fd){
	struct thread *curr = thread_current();
	if(fd < 0 || fd >= MAX_FD_NUM)
		return;
	curr->fd_table[fd] = NULL;
}


int
add_file_to_fd_table(struct file *file){
	int fd = 2;
	struct thread* curr = thread_current();
	while (curr->fd_table[fd]){
		fd++;
	}

	if(fd >= MAX_FD_NUM){
		return -1;
	}
	curr->fd_table[fd] = file;
	return fd;
}

struct
file *fd_to_struct_filep(int fd){
	struct thread *curr = thread_current();

	if(fd < 0 || fd >= MAX_FD_NUM)
		return NULL;
		
	return curr->fd_table[fd];
}


void check_address(void *addr){
	struct thread *curr = thread_current();
	/* 유저 메모리 주소에 있는지, 물리 메모리에 맵핑이 된 주소인지 확인 */
	if(!(addr && is_user_vaddr(addr) && pml4_get_page(curr->pml4, addr)))
			exit_handler(-1);
}


/* SYSTEMCALL FUCNTION */

void
exit_handler(int status){
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit(%d)\n", t->name, status); 
	thread_exit();
}

void 
halt_handler (){
	power_off();
}

/* create : 파일을 생성하는 시스템 콜 (file, initial_size) */
bool create_handler(const char * file, unsigned initial_size){
	
	check_address(file);
	lock_acquire(&filesys_lock);
	bool create_result = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return create_result;
}    

int
open_handler(const char *file){
	check_address(file);
	//lock_acquire(&filesys_lock);
	struct file *open_file = filesys_open(file);
	int fd = add_file_to_fd_table(open_file);

	if(strcmp(thread_current()->name, file) == 0){
		file_deny_write(open_file);
	}
	
	//lock_release(&filesys_lock);
	
	if(open_file == NULL){
		return -1;
	}

	if(fd == -1){
		file_close(open_file);
	}
	return fd;
}


void get_argument(void *rsp, int **arg, int count){
	rsp = (int64_t *)rsp + 2;
	for (int i = 0; i < count; i++){
		arg[i] = rsp;
		rsp = (int64_t *)rsp + 1;
	}
}



bool remove_handler(const char *file){
	check_address(file);
	//lock_acquire(&filesys_lock);
	bool remove_result = filesys_remove(file);
	//lock_release(&filesys_lock);
	return remove_result;
}

int filesize_handler(int fd){
	struct file *file_object = fd_to_struct_filep(fd);

	if(file_object == NULL){
		return -1;
	}
	//lock_acquire(&filesys_lock);
	off_t write_byte = file_length(file_object);
	//lock_release(&filesys_lock);
	return write_byte;
}

int
read_handler(int fd, void *buffer, unsigned size){
	check_address(buffer);
	// check_address(buffer + size -1);

	int read_count;
	struct file *fileobj = fd_to_struct_filep(fd);

	if (fileobj == NULL){
		return -1;
	}

	if (fd == STDOUT_FILENO){
		return -1;
	}
	lock_acquire(&filesys_lock);
	read_count = file_read(fileobj, buffer, size);
	lock_release(&filesys_lock);

	return read_count;
}


int
write_handler(int fd, const void *buffer, unsigned size){
	check_address(buffer);

	if(fd == STDIN_FILENO){
		return 0;
	} else if (fd == STDOUT_FILENO){
		putbuf(buffer, size);
		return size;
	}else {
		struct file *write_file = fd_to_struct_filep(fd);
		if(write_file == NULL){
			return 0;
		}
		//lock_acquire(&filesys_lock);
		off_t write_byte = file_write(write_file, buffer, size);
		//lock_release(&filesys_lock);
		return write_byte;
	}

}

void
seek_handler(int fd, unsigned position){
	struct file *file_object = fd_to_struct_filep(fd);
	file_seek(file_object, position);
}


unsigned
tell_handler(int fd){
	if(fd < 2)
		return;
	struct file *file_object = fd_to_struct_filep(fd);
	check_address(file_object);
	if(file_object == NULL){
		return;
	}
	return file_tell(fd);
}

void close_handler(int fd){
	struct file *close_file = fd_to_struct_filep(fd);
	if(close_file == NULL){
		return;
	}
	//lock_acquire(&filesys_lock);
	file_close(close_file);
	//lock_release(&filesys_lock);
	remove_file_from_fd_table(fd);
}


int wait_handler(pid_t pid){
	return process_wait(pid);
}


int 
fork_handler(const char * thread, struct intr_frame *f){
	return process_fork(f->R.rdi, f);
}


int 
exec_handler(char *file){
	check_address(file);

	int file_size = strlen(file)+1;
	char *fn_copy = palloc_get_page(PAL_ZERO); // 파일 네임 카피

	if (fn_copy == NULL) {
		return -1;
	}
	strlcpy (fn_copy, file, file_size);

	if (process_exec (fn_copy) == -1){
		return -1;
	}
	
	NOT_REACHED();
	return 0;

}


/* The main system call interface */
/* 시스템 콜이 레지스터 rax에 저장한 시스템 콜 넘버에 따라 각기 다른 작업을 수행한다. */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// TODO: Your implementation goes here.

	/* rax : 시스템 콜 번호 */
	int syscall_number = f->R.rax;  

	/* 인자 전달 순서 */
	// uint64_t rdi = f->R.rdi;			
	// uint64_t rsi = f->R.rsi;	
	// uint64_t rdx = f->R.rdx;
	// uint64_t r10 = f->R.r10;
	// uint64_t r8 = f->R.r8;
	// uint64_t r9 = f->R.r9;	

	switch (syscall_number) {		// rax is the system call number

		/* SYS_HALT : pintos 종료 */
		case SYS_HALT : 
			halt_handler();
			break;

		/* SYS_EXIT : */
		case SYS_EXIT : 
			exit_handler(f->R.rdi);
			break;
			
		case SYS_FORK :
			f->R.rax = fork_handler(f->R.rdi, f);
			break;

		//프로세스 생성
		case SYS_EXEC :
			f->R.rax = exec_handler(f->R.rdi);
			break;

		case SYS_WAIT :
			f->R.rax = wait_handler(f->R.rdi);
			break;

		case SYS_CREATE :
			f -> R.rax = create_handler(f->R.rdi, f->R.rsi);
			break;

		case SYS_REMOVE :
			f->R.rax = remove_handler(f->R.rdi);
			break;

		case SYS_OPEN :
			f->R.rax = open_handler(f->R.rdi);
		break;

		case SYS_FILESIZE :
			f->R.rax = filesize_handler(f->R.rdi);
			break;

		case SYS_READ :
			f->R.rax = read_handler(f->R.rdi, f->R.rsi, f->R.rdx);
			break;

		case SYS_WRITE :
			f->R.rax = write_handler(f->R.rdi, f->R.rsi, f->R.rdx);
			break;

		case SYS_SEEK :
			seek_handler(f->R.rdi, f->R.rsi);
			break;

		case SYS_TELL :
			f->R.rax = tell_handler(f->R.rdi);
			break;

		case SYS_CLOSE :
			close_handler(f->R.rdi);
			break;

	}
}
