#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	int fd, n, r;
	char buf[512+1];

	binaryname = "hyoui";

	cprintf("hyoui startup\n");

	cprintf("hyoui: open /motd\n");
	if ((fd = open("/motd", O_RDONLY)) < 0)
		panic("hyoui: open /motd: %e", fd);

	cprintf("hyoui: read /motd\n");
	while ((n = read(fd, buf, sizeof buf-1)) > 0)
		sys_cputs(buf, n);

	cprintf("hyoui: close /motd\n");
	close(fd);

	cprintf("hyoui: exec /init\n");
	if ((r = execl("/init", "init", "initarg1", "initarg2", (char*)0)) < 0)
		panic("hyoui: exec /init: %e", r);

	cprintf("hyoui: exiting\n"); // should never see it
}
