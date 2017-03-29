// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>
#include <inc/mmu.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display the backtrace", mon_backtrace },
	{ "time", "Display used cycles for the command", mon_time },
  { "memdump", "Dump the contents of a range of memory", mon_memdump },
  { "showmappings", "Display hte physical page mappings and corresponding permission bits", mon_showmappings },
  { "chmapping", "Change the permission bits of a mapping", mon_chmapping }
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

	// And you must use the "cprintf" function with %n specifier
	// you augmented in the "Exercise 9" to do this job.

	// hint: You can use the read_pretaddr function to retrieve 
	//       the pointer to the function call return address;

	char str[256] = {};
	int nstr = 0;
	int i;
	char *pret_addr = (char *)read_pretaddr();
	int retaddr = *(uint32_t *)pret_addr;
	int target = (int)do_overflow;
	for (i = 0; i < 4; ++i) {
		memset(str, '!', 256);
		str[target & 0xff] = 0;
		cprintf("%s%n", str, pret_addr + i);
		target = target >> 8;
	}
	for (i = 4; i < 8; ++i) {
		memset(str, '!', 256);
		str[retaddr & 0xff] = 0;
		cprintf("%s%n", str, pret_addr + i);
		retaddr = retaddr >> 8;
	}
}

void
overflow_me(void)
{
        start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	int i;
	cprintf("Stack backtrace:\n");
	uint32_t cur = read_ebp();
	while (cur) {
		uint32_t eip = *(uint32_t *)(cur + 4);
		cprintf("  eip %08x ebp %08x args %08x %08x %08x %08x %08x\n", eip, cur, *(uint32_t *)(cur + 8),
			*(uint32_t *)(cur + 12), *(uint32_t *)(cur + 16), *(uint32_t *)(cur + 20), *(uint32_t *)(cur + 24));
		struct Eipdebuginfo info;
		debuginfo_eip(eip, &info);
		cprintf("\t %s:%d ", info.eip_file, info.eip_line);
		for (i = 0; i < info.eip_fn_namelen; ++i) {
			cprintf("%c", info.eip_fn_name[i]);
		}
		cprintf("+%d\n", eip - (uint32_t)info.eip_fn_addr);
		cur = *(uint32_t *)cur;
	}
	overflow_me();
	cprintf("Backtrace success\n");
	return 0;
}

static unsigned long long read_time_stamp_counter()
{
	unsigned long long tick;
	__asm__ __volatile__("rdtsc":"=A"(tick));
	return tick;
}

int
mon_time(int argc, char **argv, struct Trapframe *tf)
{
	int i, start, end;
	if (argc < 2)
		return 0;
	int new_argc = argc - 1;
	char **new_argv = argv + 1;
	// Lookup and invoke the command
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(new_argv[0], commands[i].name) == 0) {
			start = read_time_stamp_counter();
			commands[i].func(new_argc, new_argv, tf);
			end = read_time_stamp_counter();
			break;
		}
	}
	if (i < NCOMMANDS) {
		cprintf("%s cycles: %ld\n", new_argv[0], end - start);
	}
	else {
		cprintf("Unknown command '%s'\n", new_argv[0]);
	}
	return 0;
}

int
hex2int(char* s)
{
        int i, res = 0;
        if (s[0] != '0' || s[1] != 'x') {
                return res;
        }

        i = 2;
        while (s[i] != '\0') {
                res *= 16;
                if (s[i] >= '0' && s[i] <= '9') {
                        res += s[i] - '0';
                }
                else if (s[i] >= 'a' && s[i] <= 'f'){
                        res += s[i] - 'a' + 10;
                }
                else {
                        return 0;
                }
                ++i;
        }
        return res;
}

int
mon_memdump(int argc, char **argv, struct Trapframe *tf)
{
        int i, start, end, kind;
        if (argc != 4) {
                cprintf("Usage: < -v | -p > <begin> <end>\n");
                return 0;
        }
        if (strcmp(argv[1], "-v") == 0) {
                kind = 0;
        }
        else if (strcmp(argv[1], "-p") == 0) {
                kind = 1;
        }
        else {
                cprintf("Usage: < -v | -p > <begin> <end>\n");
                return 0;
        }
        start = hex2int(argv[2]);
        end = hex2int(argv[3]);

        cprintf("0x%x:", start);
        int cnt = 0;
        for (i = start; i <= end; ++i) {
                if (cnt == 8) {
                        cnt = 0;
                        cprintf("\n0x%x:", i);
                }
                if (kind) {
                        cprintf(" %02x", ((unsigned int)*(char *)(i + KERNBASE)) & 0xff);
                }
                else {
                        cprintf(" %02x", ((unsigned int)*(char *)i) & 0xff);
                }
                cnt++;
        }
        cprintf("\n");
        return 0;
}

int mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
        int i, start, end, cur;
        if (argc != 3) {
                cprintf("Usage: <begin> <end>\n");
                return 0;
        }
        start = hex2int(argv[1]);
        end = hex2int(argv[2]);
        i = start;
        pte_t *pte;
        while (i <= end) {
                pte = pgdir_walk(kern_pgdir, (void *)i, 0);
                if (pte && (*pte & PTE_P)) {
                        if (*pte & PTE_PS) {
                                cur = PDX(i) << PDXSHIFT;
                                i = cur + PTSIZE;
                        }
                        else {
                                cur = PGNUM(i) << PTXSHIFT;
                                i = cur + PGSIZE;
                        }
                        cprintf("0x%08x => 0x%08x", cur, PGNUM(*pte) << PTXSHIFT);
                        if (*pte & PTE_W) {
                                cprintf(" W");
                        }
                        if (*pte & PTE_U) {
                                cprintf(" U");
                        }
                        if (*pte & PTE_PWT) {
                                cprintf(" PWT");
                        }
                        if (*pte & PTE_PCD) {
                                cprintf(" PCD");
                        }
                        if (*pte & PTE_A) {
                                cprintf(" A");
                        }
                        if (*pte & PTE_D) {
                                cprintf(" D");
                        }
                        if (*pte & PTE_PS) {
                                cprintf(" PS");
                        }
                        if (*pte & PTE_G) {
                                cprintf(" G");
                        }
                        cprintf("\n");
                }
                else {
                        cur = PGNUM(i) << PTXSHIFT;
                        cprintf("0x%08x => NOT EXIST\n", cur);
                        i = cur + PGSIZE;
                }
        }
        return 0;
}

int mon_chmapping(int argc, char **argv, struct Trapframe *tf)
{
        int perm, op, addr;
        if (argc != 3) {
                cprintf("Usage: <option> <addr>\n");
                return 0;
        }
        if (argv[1][0] == '-') {
                op = 0;
        }
        else if (argv[1][0] == '+') {
                op = 1;
        }
        else {
                cprintf("Usage: <option> <addr>\n");
                return 0;
        }
        if (strcmp(argv[1] + 1, "W") == 0) {
                perm = PTE_W;
        } else if (strcmp(argv[1] + 1, "U") == 0) {
                perm = PTE_U;
        } else if (strcmp(argv[1] + 1, "PWT") == 0) {
                perm = PTE_PWT;
        } else if (strcmp(argv[1] + 1, "PCD") == 0) {
                perm = PTE_PCD;
        } else if (strcmp(argv[1] + 1, "A") == 0) {
                perm = PTE_A;
        } else if (strcmp(argv[1] + 1, "D") == 0) {
                perm = PTE_D;
        } else if (strcmp(argv[1] + 1, "G") == 0) {
                perm = PTE_G;
        } else {
                cprintf("Usage: <option> <addr>\n");
                return 0;
        }

        addr = hex2int(argv[2]);
        pte_t *pte = pgdir_walk(kern_pgdir, (void *)addr, 0);
        if (pte) {
                if (op) {
                        *pte = *pte | perm;
                }
                else {
                        *pte = *pte & ~perm;
                }
        }
        return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
