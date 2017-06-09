#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pmap.h>
#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>

static volatile char *e1000_bar0 = (char *)KSTACKTOP;
static volatile struct tx_desc *tx_descs = (struct tx_desc *)(IOMEMBASE - DMA_PAGES * PGSIZE);
static volatile struct tx_pkt *tx_pkts = (struct tx_pkt *)(IOMEMBASE - (DMA_PAGES - 256) * PGSIZE);
static volatile struct rcv_desc *rcv_descs = (struct rcv_desc *)(IOMEMBASE - (DMA_PAGES - 512) * PGSIZE);
static volatile struct rcv_pkt *rcv_pkts = (struct rcv_pkt *)(IOMEMBASE - (DMA_PAGES - 768) * PGSIZE);
extern size_t npages;			// Amount of physical memory (in pages)

uint8_t e1000_mac[6];

static uint16_t e1000_read_eeprom(uint8_t addr)
{
  volatile uint32_t *eerd = (uint32_t *)(e1000_bar0 + E1000_EERD);
  *eerd = (addr << 8) | E1000_EERD_START;
  while ((*eerd & E1000_EERD_DONE) == 0)
    ; /* nop */
  return *eerd >> 16;
}

static void e1000_init_mem()
{
  int i;
  memset((void *)(IOMEMBASE - DMA_PAGES * PGSIZE), 0, DMA_PAGES * PGSIZE);

  for (i = 0; i < E1000_NTXDESC; ++i) {
    tx_descs[i].status |= E1000_TXDESC_STATUS_DD;
    tx_descs[i].addr = (npages - DMA_PAGES + 256) * PGSIZE + i * sizeof(struct tx_pkt);
  }

  for (i = 0; i < E1000_NRCVDESC; ++i) {
    rcv_descs[i].addr = (npages - DMA_PAGES + 768) * PGSIZE + i * sizeof(struct rcv_pkt);
  }
}

int e1000_transmit(const char * buf, uint32_t len)
{
  if (len > E1000_TX_PKT_LEN)
    return -E_INVAL;

  volatile uint32_t *tdt = (uint32_t *)(e1000_bar0 + E1000_TDT);
  uint32_t cur = *tdt;
  if (!(tx_descs[cur].status & E1000_TXDESC_STATUS_DD))
    return -E_TX_QUEUE_FULL;

  memmove((void *)tx_pkts[cur].pkt, buf, len);
  tx_descs[cur].length = len;
  tx_descs[cur].status &= ~E1000_TXDESC_STATUS_DD;
  tx_descs[cur].cmd |= E1000_TXDESC_CMD_RS;
  tx_descs[cur].cmd |= E1000_TDESC_CMD_EOP;

  uint32_t next = cur + 1;
  if (next == E1000_NTXDESC)
    next = 0;
  *tdt = next;
  return 0;
}

int e1000_receive(char * buf)
{
  int len;
  volatile uint32_t *rdt = (uint32_t *)(e1000_bar0 + E1000_RDT);
  uint32_t cur = (*rdt + 1) % E1000_NRCVDESC;

  if (!(rcv_descs[cur].status & E1000_RCVDESC_STATUS_DD))
    return -E_RCV_QUEUE_EMPTY;

  len = rcv_descs[cur].length;
  memmove(buf, (void *)rcv_pkts[cur].pkt, len);
  rcv_descs[cur].status &= ~E1000_RCVDESC_STATUS_DD;

  *rdt = cur;
  return len;
}

int e1000_attach(struct pci_func *pcif)
{
  pci_func_enable(pcif);
  boot_map_region(kern_pgdir, (uint32_t)e1000_bar0, pcif->reg_size[0], pcif->reg_base[0], PTE_W|PTE_PCD|PTE_PWT);
  volatile uint32_t *p_status = (uint32_t *)(e1000_bar0 + E1000_STATUS);
  cprintf("e1000 status: 0x%x\n", *p_status);

  e1000_init_mem();

  // Initialize TDBAL/TDBAH
  volatile uint32_t *tdbal = (uint32_t *)(e1000_bar0 + E1000_TDBAL);
  *tdbal = (npages - DMA_PAGES) * PGSIZE;
  volatile uint32_t *tdbah = (uint32_t *)(e1000_bar0 + E1000_TDBAH);
  *tdbah = 0;

  // Initialize TDLEN
  volatile uint32_t *tdlen = (uint32_t *)(e1000_bar0 + E1000_TDLEN);
  *tdlen = sizeof(struct tx_desc) * E1000_NTXDESC;

  // Initialize Transmit Descriptor Head / Tail
  volatile uint32_t *tdh = (uint32_t *)(e1000_bar0 + E1000_TDH);
  *tdh = 0;
  volatile uint32_t *tdt = (uint32_t *)(e1000_bar0 + E1000_TDT);
  *tdt = 0;

  // Initialize Transmit Control Register
  volatile uint32_t *tctl = (uint32_t *)(e1000_bar0 + E1000_TCTL);
  *tctl |= E1000_TCTL_EN;
  *tctl |= E1000_TCTL_PSP;
  *tctl |= E1000_TCTL_CT;
  *tctl |= E1000_TCTL_COLD;

  // Initialize TIPG
  volatile uint32_t *tipg = (uint32_t *)(e1000_bar0 + E1000_TIPG);
  *tipg |= E1000_TIPG_IPGT;
  *tipg |= E1000_TIPG_IPGR1;
  *tipg |= E1000_TIPG_IPGR2;

  // Initialize Receive Address
  uint32_t mac_l = e1000_read_eeprom(0x0);
  uint32_t mac_m = e1000_read_eeprom(0x1);
  uint32_t mac_h = e1000_read_eeprom(0x2);
  e1000_mac[0] = mac_l & 0xff;
  e1000_mac[1] = (mac_l >> 8) & 0xff;
  e1000_mac[2] = mac_m & 0xff;
  e1000_mac[3] = (mac_m >> 8) & 0xff;
  e1000_mac[4] = mac_h & 0xff;
  e1000_mac[5] = (mac_h >> 8) & 0xff;
  cprintf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
          e1000_mac[0], e1000_mac[1], e1000_mac[2], e1000_mac[3], e1000_mac[4], e1000_mac[5]);
  volatile uint32_t *ral = (uint32_t *)(e1000_bar0 + E1000_RAL);
  *ral = (mac_m << 16) | mac_l;
  volatile uint32_t *rah = (uint32_t *)(e1000_bar0 + E1000_RAH);
  *rah = mac_h;
  *rah |= E1000_RAH_VALID;

  // Initialize RDBAL/RDBAH
  volatile uint32_t *rdbal = (uint32_t *)(e1000_bar0 + E1000_RDBAL);
  *rdbal = (npages - DMA_PAGES + 512) * PGSIZE;
  volatile uint32_t *rdbah = (uint32_t *)(e1000_bar0 + E1000_RDBAH);
  *rdbah = 0;

  // Initialize RDLEN
  volatile uint32_t *rdlen = (uint32_t *)(e1000_bar0 + E1000_RDLEN);
  *rdlen = E1000_NRCVDESC << 6;

  // Initialize Receive Descriptor Head / Tail
  volatile uint32_t *rdh = (uint32_t *)(e1000_bar0 + E1000_RDH);
  *rdh = 0;
  volatile uint32_t *rdt = (uint32_t *)(e1000_bar0 + E1000_RDT);
  *rdt = E1000_NRCVDESC - 1;

  // Initialize Receive Control Register
  volatile uint32_t *rctl = (uint32_t *)(e1000_bar0 + E1000_RCTL);
  *rctl = E1000_RCTL_EN | E1000_RCTL_SZ_2048 | E1000_RCTL_SECRC;

  return 1;
}
