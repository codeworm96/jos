#include "ns.h"
#include <inc/lib.h>

extern union Nsipc nsipcbuf;

void
output(envid_t ns_envid)
{
  int r;
	binaryname = "ns_output";

	// LAB 6: Your code here:
	// 	- read a packet from the network server
	//	- send the packet to the device driver

  for (;;) { // forever
    r = ipc_recv(NULL, &nsipcbuf, NULL);
    if (r == NSREQ_OUTPUT) {
      while (sys_net_try_transmit(nsipcbuf.pkt.jp_data, nsipcbuf.pkt.jp_len) == -E_TX_QUEUE_FULL)
        ; // empty body
    }
  }
}
