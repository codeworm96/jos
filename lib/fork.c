// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) ROUNDDOWN(utf->utf_fault_va, PGSIZE);
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).
  if (!(err & FEC_WR)) {
    panic("pgfault: faulting access is not a write");
  }
  if (!(vpd[PDX(addr)] & PTE_P) ||
      !(vpt[PGNUM(addr)] & PTE_P) || !(vpt[PGNUM(addr)] & PTE_COW)) {
    panic("pgfault: faulting access is not to a copy-on-write page");
  }

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.
	r = sys_page_alloc(0, PFTEMP, PTE_P|PTE_U|PTE_W);
	if (r < 0)
		panic("sys_page_alloc: %e", r);

	memmove(PFTEMP, addr, PGSIZE);

	r = sys_page_map(0, PFTEMP, 0, addr, PTE_P|PTE_U|PTE_W);
	if (r < 0)
		panic("sys_page_map: %e", r);

	r = sys_page_unmap(0, PFTEMP);
	if (r < 0)
		panic("sys_page_unmap: %e", r);
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
  void *addr = (void *)(pn * PGSIZE);
  if ((vpd[PDX(addr)] & PTE_P) && (vpt[pn] & PTE_P)) {
    if (vpt[pn] & (PTE_W | PTE_COW)) {
      // The ordering is important
      r = sys_page_map(0, addr, envid, addr, PTE_P|PTE_U|PTE_COW);
      if (r < 0) {
        return r;
      }
      r = sys_page_map(0, addr, 0, addr, PTE_P|PTE_U|PTE_COW);
      if (r < 0) {
        return r;
      }
    } else {
      r = sys_page_map(0, addr, envid, addr, PTE_P|PTE_U);
      if (r < 0) {
        return r;
      }
    }
  }
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	envid_t envid;
  unsigned pn, end;
	int r;

  set_pgfault_handler(pgfault);

	// Allocate a new child environment.
	// The kernel will initialize it with a copy of our register state,
	// so that the child will appear to have called sys_exofork() too -
	// except that in the child, this "fake" call to sys_exofork()
	// will return 0 instead of the envid of the child.
	envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	// We're the parent.
  // Copy our address space with copy-on-write duppage
  end = UTOP / PGSIZE;
  for (pn = 0; pn < end; ++pn) {
    //   Neither user exception stack should ever be marked copy-on-write,
    if (pn != UXSTACKTOP / PGSIZE - 1) {
      r = duppage(envid, pn);
      if (r < 0) {
        panic("fork: failed to duppage");
      }
    }
  }

  // Allocate exception stack for child
  r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_W | PTE_U | PTE_P);
  if (r < 0) {
    panic("fork: exception stack allocation failed!");
  }

  // set pgfault upcall for child
  extern void _pgfault_upcall(void);
  r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall);
  if (r < 0) {
    panic("fork: set_pgfault_upcall failed!");
  }

	// set the child environment runnable
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", r);

	return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
