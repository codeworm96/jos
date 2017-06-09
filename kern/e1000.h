#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>

#define E1000_VENDOR_ID 0x8086
#define E1000_DEVICE_ID 0x100e

#define E1000_NTXDESC  32
#define E1000_NRCVDESC 128
#define E1000_TX_PKT_LEN  1518
#define E1000_RCV_PKT_LEN 2048

#define E1000_STATUS   0x00008  /* Device Status - RO */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
#define E1000_TCTL     0x00400  /* TX Control - RW */
#define E1000_TCTL_EN (0x1 << 1)     // Transmit Enable
#define E1000_TCTL_PSP (0x1 << 3)    // Pad Short Packets
#define E1000_TCTL_CT  (0x10 << 4)   // Collision Threshold
#define E1000_TCTL_COLD (0x40 << 12) // Collision Distance - full duplex
#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */
#define E1000_TIPG_IPGT 10          // Transmit Time
#define E1000_TIPG_IPGR1 (8 << 10) // IPG Receive Time 1
#define E1000_TIPG_IPGR2 (6 << 20) // IPG Receive Time 2

#define E1000_TXDESC_CMD_RS (0x1 << 3) // Report Status
#define E1000_TDESC_CMD_EOP (0x1)     // End of Packet
#define E1000_TXDESC_STATUS_DD (0x1)   // Descriptor Done

#define E1000_RAL      0x05400  /* Receive Address Low - RW */
#define E1000_RAH      0x05404  /* Receive Address High - RW */
#define E1000_RAH_VALID (0x1 << 31)
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_RCTL_EN             0x00000002    /* enable */
#define E1000_RCTL_SZ_2048        0x00000000    /* rx buffer size 2048 */
#define E1000_RCTL_SECRC          0x04000000    /* Strip Ethernet CRC */

#define E1000_RCVDESC_STATUS_DD 0x1         // Descriptor Done

#define E1000_EERD     0x00014  /* EEPROM Read - RW */
#define E1000_EERD_START    0x1
#define E1000_EERD_DONE     0x10

int e1000_attach(struct pci_func *pcif);
int e1000_transmit(const char * buf, uint32_t len);
int e1000_receive(char * buf);

struct tx_desc
{
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
} __attribute__((packed));

struct tx_pkt
{
  char pkt[E1000_TX_PKT_LEN];
};

struct rcv_desc
{
	uint64_t addr;
	uint16_t length;
  uint16_t checksum;
	uint8_t status;
	uint8_t errors;
	uint16_t special;
} __attribute__((packed));

struct rcv_pkt
{
  char pkt[E1000_RCV_PKT_LEN];
};

#endif	// JOS_KERN_E1000_H
