#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
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
#include "threads/synch.h"
#include "userprog/process.h"
#include "lib/string.h"
#include "threads/palloc.h"


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

struct page* check_address(void *addr)
{
	/* 주소 addr이 유저 가상 주소가 아니거나 pml4에 없으면 프로세스 종료 */
	if (addr == NULL || !is_user_vaddr(addr))
	{
		sys_exit_handler(-1);
	}
	/* 유저 가상 주소면 SPT에서 페이지 찾아서 리턴 */
	return spt_find_page(&thread_current()->spt, addr);
}

void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write){
	/* 버퍼 내의 시작부터 끝까지의 각 주소를 모두 check_address*/
	for (int i = 0; i < size; i++){
		struct page* page = check_address(buffer + i); 

		/* 해당 주소가 포함된 페이지가 spt에 없다면 */
		if(page == NULL)
			sys_exit_handler(-1);

		/* write 시스템 콜을 호출했는데 이 페이지가 쓰기가 허용된 페이지가 아닌 경우 */
		if(to_write == true && page->writable == false)
			sys_exit_handler(-1);
	}
}



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

void
sys_halt_handler(){
	power_off();
}

void
sys_exit_handler(int arg1){
	thread_current()->my_exit_code = arg1;
	thread_exit();
}

bool sys_create_handler(char *filename, unsigned intial_size){
	bool result;
	struct thread *curr = thread_current();
	if(!check_address(filename)){
		sys_exit_handler(-1);
	}
	lock_acquire(&filesys_lock);
	result = filesys_create(filename, intial_size);
	lock_release(&filesys_lock);
	return result;
}

bool sys_remove_handler(char *filename){
	bool result;
	lock_acquire(&filesys_lock);
	result = filesys_remove(filename);
	lock_release(&filesys_lock);
	return result;
}

int sys_open_handler(char *filename){
	// return -1;
	struct thread *curr = thread_current();
	if(!check_address(filename)){
		sys_exit_handler(-1);
	}

	lock_acquire(&filesys_lock);
	struct file *file = filesys_open(filename);
	lock_release(&filesys_lock);
	if (!file)
		return -1;

	struct file **f_table = curr->fd_table;
	int i = FDBASE;
	for (i; i < FDLIMIT; i++)
	{
		if (f_table[i] == NULL){
			f_table[i] = file;
			return i;
		}
	}
	lock_acquire(&filesys_lock);
	file_close(file);
	lock_release(&filesys_lock);
	return -1;
}

int sys_close_handler(int fd){
	struct file **f_table = thread_current()->fd_table;
	if (fd < FDBASE || fd >= FDLIMIT){
		thread_current()->my_exit_code = -1;
		thread_exit();
	}
	else if (f_table[fd]){
		lock_acquire(&filesys_lock);
		file_close(f_table[fd]);
		lock_release(&filesys_lock);
		f_table[fd] = NULL;
	}
	else{
		thread_current()->my_exit_code = -1;
		thread_exit();
	}
}

int sys_filesize_handler(int fd){
	int result;
	struct thread *curr = thread_current();
	struct file **f_table = curr->fd_table;
	struct file *f = f_table[fd]; 
	lock_acquire(&filesys_lock);
	result =  file_length(f);
	lock_release(&filesys_lock);
	return result;
}

int sys_read_handler(int fd, void* buffer, unsigned size){
	struct thread *curr = thread_current();
	int result;
	if (fd < FDBASE || fd >= FDLIMIT || curr->fd_table[fd] == NULL)
	{
		thread_current()->my_exit_code = -1;
		thread_exit();
	}
	struct file *f = curr->fd_table[fd];
	lock_acquire(&filesys_lock);
	result = file_read(f, buffer, size);
	lock_release(&filesys_lock);
	return result;
}

int sys_write_handler(int fd, void *buffer, unsigned size){
	struct thread *curr = thread_current();
	int result;
	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
		
	}
	if (fd < FDBASE || fd >= FDLIMIT || curr->fd_table[fd] == NULL ) 
	{
		curr->my_exit_code = -1;
		thread_exit();
	}
	struct file *f = curr->fd_table[fd];
	lock_acquire(&filesys_lock);
	result = file_write(f, buffer, size);
	lock_release(&filesys_lock);
	return result;
}

int sys_fork_handler(char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

int sys_wait_handler(int pid){
	return process_wait(pid);
}

int sys_exec_handler(char * cmd_line){
	struct thread *curr = thread_current();
	if(!check_address(cmd_line)){
		sys_exit_handler(-1);
	}

 	char *fn_copy = palloc_get_page (0);
	strlcpy (fn_copy, cmd_line, PGSIZE);
	return process_exec(fn_copy);
}

void 
sys_seek_handler(int fd, unsigned position){
	struct thread *curr = thread_current ();
	struct file **f_table = curr->fd_table;
	if (fd < FDBASE || fd >= FDLIMIT || curr->fd_table[fd] == NULL) {
		curr->my_exit_code = -1;
		thread_exit();
	}
	struct file *f = f_table[fd];
	lock_acquire(&filesys_lock);
	file_seek(f, position);
	lock_release(&filesys_lock);
	
}

void
* sys_mmap_handler (void *addr, size_t length, int writable, int fd, off_t offset){
  if(offset % PGSIZE != 0 ) // 우리는 모든걸 PGSIZE에 맞춰서 사용하기 때문에 PGSIZE가 아닌 경우 return NULL
    return NULL;

  if (pg_round_down(addr) != addr || is_kernel_vaddr(addr) || addr == NULL || (long long)length <=0){
  // pg_round_down(addr) != addr --> input된 addr이 page 주소가 맞는지 확인
  // is_kernel_vaddr (addr) --> addr 가 kernel에 위치하고 있는지
  // addr == NULL --> addr이 NULL 인지
  // (long long) length <= 0 --> input 된 크기가 0 이상인지
    return NULL;
  }
  
  if (fd == 0 || fd == 1){
    // fd 가 0이나 1이라는 의미는 STDIN, STDOUT 이라는 의미이니깐 들어오면 안되는 애가 들어온거 --> exit로 보내버림
    exit_handler(-1);
  }
  
  if(spt_find_page(&thread_current()->spt, addr)){
    // addr 가 spt table에 존재하고 있는지 확인
    return NULL;
  }
  
  struct file * target = find_file_using_fd(fd); // fd가 존재하는거니깐 fd에 맞는 file을 찾고

  if(target == NULL)
    return NULL;
  
  void *ret = do_mmap(addr, length, writable, target, offset); 
  //fd로 열린 파일의 오프셋 바이트부터 length 바이트 만큼을 프로세스의 가상주소공간의 주소 addr 에 매핑 합니다

  return ret;
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) { 
	// TODO: Your implementation goes here.
	#ifdef VM
		thread_current()->rsp_stack = f->rsp;
	#endif
		int syscall_n = f->R.rax;
		switch (syscall_n)
		{
		case SYS_HALT:
			sys_halt_handler();
			break;
		case SYS_EXIT:
			sys_exit_handler(f->R.rdi);
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
			f->R.rax = sys_filesize_handler(f->R.rdi);
			break;
		case SYS_CLOSE:
			f->R.rax = sys_close_handler(f->R.rdi);
			break;
		case SYS_READ:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
			f->R.rax = sys_read_handler(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
			f->R.rax = sys_write_handler(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_FORK:
			f->R.rax = sys_fork_handler(f->R.rdi, f);
			break;
		case SYS_WAIT:
			f->R.rax = sys_wait_handler(f->R.rdi);
			break;
		case SYS_EXEC:
			sys_exec_handler(f->R.rdi);
			break;
		case SYS_SEEK:
			sys_seek_handler(f->R.rdi,f->R.rsi);
			break;
		case SYS_MMAP:
			f->R.rax = sys_mmap_handler(f->R.rdi,f->R.rsi, f->R.rdx, f->R.r10, f->R.r8 );
		default:
			break;
		}
}
