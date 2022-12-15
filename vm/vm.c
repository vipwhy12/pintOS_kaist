/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "lib/kernel/hash.h"
#include "userprog/process.h"


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
unsigned hash_func(const struct hash_elem *p_, void *aux UNUSED);
bool less_func(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* project03 : hash init을 위한 함수 */

/* hash table을 초기화 할 때, hash값을 구해주는 함수 포인터 */
unsigned
hash_func(const struct hash_elem *p_, void *aux UNUSED){
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* hash table을 초기화 할 때, 해시 요소들을 비교하는 함수의 포인터 */
/* 왜 비교해줄까? */
bool
less_func(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
	/* a_가 b_ 보다 작으면 true, 반대면 false */
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */


/* initializer를 사용해서 보류중인 페이지 객체를 만듭니다.
 * 페이지를 생성하려면 직접 생성하지 말고 이 함수 또는 vm_alloc_page를 통해 생성하세요 */
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage, 
		bool writable, vm_initializer *init, void *aux) 
{
	ASSERT (VM_TYPE(type) != VM_UNINIT) // 인자로 들어오는 TYPE은 ANON 아니면 FILE-BACKED

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {  /* spt안에 upage에 해당하는 페이지가 없으면 */
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* 함수 포인터를 사용하여 TYPE에 맞는 페이지 초기화 함수를 사용한다. */
		typedef bool (*initializeFunc)(struct page*, enum vm_type, void *);
		initializeFunc initializer = NULL;

		switch(VM_TYPE(type)){
			case VM_ANON:
			// case VM_ANON|VM_MARKER_0:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
			default:
				goto err;
		} 

		/* 새 페이지를 만들어서 page 구조체의 멤버를 채운다. */
		struct page *new_page = malloc(sizeof(struct page));
		uninit_new(new_page, upage, init, type, aux, initializer);

		new_page->writable = writable;
		new_page->page_cnt = -1;  // file-mapped page가 아니므로 -1.

		/* TODO: Insert the page into the spt. */
		/* 새로 만든 UNINIT 페이지를 프로세스의 spt에 넣는다. 
		   아직 물리 메모리랑 매핑이 된 것도 아니고 타입에 맞춰 초기화도 되지 않았다. */
	
		if(!spt_insert_page(spt, new_page)){
			goto err;
		}
		/*spt find하고 null이면 error로 보내줘요*/
		return true;
	}
err:
	return false;
}


/* Find VA from spt and return page. On error, return NULL. */
/* SPT 및 반환 페이지에서 VA를 찾습니다. 오류가 발생하면 NULL을 반환합니다. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = (struct page*)malloc(sizeof(struct page));
	struct hash_elem *e;

	/* 해당 va가 속해 있는 페이지 시작 주소를 가지는 page를 만든다. */
	/* 해당 페이지가 spt에 있는지 확인 할 것 */
	page->va = pg_round_down(va);

	/* e와 같은 해시값(va)를 가지는 원소를 e에 해당하는 bucketlist 내에서 찾아서 리턴 */
	e = hash_find(&spt->pages, &page->hash_elem);

	free(page);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	
	/* 반환값이 NULL이면 성공 */
	if(!hash_insert(&spt->pages, &page->hash_elem))
		succ = true;

	return succ;
	}

bool
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	if(!hash_delete(&spt->pages, &page->hash_elem)){
		return true; 
	}
	return false;
}

/* Get the struct frame, that will be evicted. */
/* 제거될 구조 프레임을 가져옵니다.*/
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	 /* TODO: 퇴거 정책은 당신에게 달렸어요.(frame에서 쫓겨낼 frame 알고리즘을 선택하라는 것 같음)*/
	victim = list_entry(list_pop_front (&frame_table), struct frame, frame_elem);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
/* 한 페이지를 삭제하고 해당 프레임을 반환합니다. 오류시, NULL반환 */
static struct frame *vm_evict_frame (void) 
{
	struct frame *victim UNUSED = vm_get_victim ();
	if(swap_out(victim->page))
		return victim;
	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* palloc을 하고, frame을 get하세요. 사용 가능한 페이지가 없는 경우 페이지를 삭제하고 반환합니다.
 * 항상 유효한 주소를 반환합니다. 
 * 즉, user 물리 메로리가 가득찰 경우에는 사용가능한 메모리 공간을 얻기 위해 프레임을 제거합니다.*/
static struct frame *
vm_get_frame (void) {
	//struct frame *frame = NULL;
	/* TODO: Fill this function. */
	
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));
	/* USER POOL에서 커널 가상 주소 공간으로 1page 할당 */
	frame->kva = palloc_get_page(PAL_USER);

	/* if 프레임이 꽉 차서 할당받을 수 없다면 페이지 교체 실시
	   else 성공했다면 frame 구조체 커널 주소 멤버에 위에서 할당받은 메모리 커널 주소 넣기 */
  if(frame->kva == NULL){
  // frame = vm_evict_frame();
    frame->page = NULL;
    return frame;
  }
    // list_push_back (&frame_table, &frame->frame_elem);

  frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	/* 스택에 해당하는 ANON페이지를 UNINIT으로 만들고 SPT에 넣어준다.*/
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault(struct intr_frame *f UNUSED, void * addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED){
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;

	/* 유저 가상 메모리 안의 페이지가 아니라면 여기서 끝낸다. */
	if(is_kernel_vaddr(addr)){
		return false;
	}

	/* 페이지의 Present bit이 0이면 메모리 상에 존재하지 않으면 메모리에 프레임을 올리고,
	* 메모리에 프레임을 올리고 프레임과 페이지를 매핑시켜준다. */
	// if(not_present){
	// 	if(!vm_claim_page(addr)){
	// 		return false;
	// 	} else {
	// 		return true;
	// 	}
	// 	return false;
	// }

	/* not_preset가 true 없다는거야 가져와야하는건데 */
	/* sptfind table : 일단 넣어놔 */
	/* addr를 가리켜서 pagefault 발생 주소가 포함되어 있는 주소 */
	if(not_present){
		page = spt_find_page(spt, addr);
		if(page == NULL)
			return false;
		/*가상메모리의 page */
		return vm_do_claim_page(page);
	}

	return false;

}


/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
/* 페이지를 va에 할당합니다.*/
bool
vm_claim_page (void *va UNUSED) {
	/* TODO: Fill this function */
	ASSERT(is_user_vaddr(va));
	struct page *page;
	page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL){
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
/* page를 할당하고 MMU를 설정합니다. */
/*spt page table */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *t = thread_current();
	
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* TODO: 페이지 테이블 항목을 삽입하여 페이지의 VA를 프레임의 PA에 매핑합니다. */
	if(	pml4_get_page (t->pml4, page->va) == NULL
         && pml4_set_page (t->pml4, page->va, frame->kva, page->writable)){
		return swap_in(page, frame->kva);
	} else{
		return false;
	}

}

/* Initialize new supplemental page table */
/* 보조 페이지 테이블을 초기화 합니다.*/
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->pages, hash_func, less_func, NULL);
}

bool supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
	struct supplemental_page_table *src UNUSED) {

	struct hash_iterator i;

	/* 1. SRC의 해시 테이블의 각 bucket 내 elem들을 모두 복사한다. */
	hash_first (&i, &src->pages);
  while (hash_next (&i)) {	// src의 각각의 페이지를 반복문을 통해 복사
      struct page *parent_page = hash_entry (hash_cur (&i), struct page, hash_elem);   // 현재 해시 테이블의 element 리턴
      enum vm_type type = page_get_type(parent_page);		// 부모 페이지의 type
      void *upage = parent_page->va;				    		// 부모 페이지의 가상 주소
      bool writable = parent_page->writable;				// 부모 페이지의 쓰기 가능 여부
      vm_initializer *init = parent_page->uninit.init;	// 부모의 초기화되지 않은 페이지들 할당 위해 
      void* aux = parent_page->uninit.aux;

			// 부모 페이지가 STACK이라면 setup_stack() : 없어도 되는듯
      if (parent_page->uninit.type & VM_MARKER_0) { 
          (&thread_current()->tf);
      }
			// 부모 타입이 uninit인 경우
      else if(parent_page->operations->type == VM_UNINIT) { 
          if(!vm_alloc_page_with_initializer(type, upage, writable, init, aux))
					// 자식 프로세스의 유저 메모리에 UNINIT 페이지를 하나 만들고 SPT 삽입.
              return false;
      }
			// STACK도 아니고 UNINIT도 아니면 vm_init 함수를 넣지 않은 상태에서 
      else {  
          if(!vm_alloc_page(type, upage, writable)) // uninit 페이지 만들고 SPT 삽입.
              return false;
          if(!vm_claim_page(upage))  // 바로 물리 메모리와 매핑하고 Initialize한다.
              return false;
      }

			// UNIT이 아닌 모든 페이지(stack 포함)에 대응하는 물리 메모리 데이터를 부모로부터 memcpy
      if (parent_page->operations->type != VM_UNINIT) { 
          struct page* child_page = spt_find_page(dst, upage);
          memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
      }
  }
  return true;
}

void supplemental_page_table_destructor(struct hash_elem *e, void *aux){
	const struct page *p = hash_entry(e, struct page, hash_elem);
	free(p);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_destroy(&spt->pages, supplemental_page_table_destructor);
}