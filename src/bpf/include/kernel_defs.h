#ifndef KERNEL_DEFS_H
#define KERNEL_DEFS_H

#include "vmlinux.h"

/* ========================================================================= *
 * linux/socket.h                                                            *
 * ========================================================================= */

/* Supported address families.
 * https://elixir.bootlin.com/linux/v5.10/source/include/linux/socket.h#L175 */
#define AF_UNSPEC 0
#define AF_UNIX 1      /* Unix domain sockets            */
#define AF_LOCAL 1     /* POSIX name for AF_UNIX         */
#define AF_INET 2      /* Internet IP Protocol           */
#define AF_AX25 3      /* Amateur Radio AX.25            */
#define AF_IPX 4       /* Novell IPX                     */
#define AF_APPLETALK 5 /* AppleTalk DDP              */
#define AF_NETROM 6    /* Amateur Radio NET/ROM          */
#define AF_BRIDGE 7    /* Multiprotocol bridge           */
#define AF_ATMPVC 8    /* ATM PVCs                       */
#define AF_X25 9       /* Reserved for X.25 project      */
#define AF_INET6 10    /* IP version 6                   */
#define AF_ROSE 11     /* Amateur Radio X.25 PLP         */
#define AF_DECnet 12   /* Reserved for DECnet project    */
#define AF_NETBEUI 13  /* Reserved for 802.2LLC project  */
#define AF_SECURITY 14 /* Security callback pseudo AF    */
#define AF_KEY 15      /* PF_KEY key management API      */
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET 17        /* Packet family                  */
#define AF_ASH 18           /* Ash                            */
#define AF_ECONET 19        /* Acorn Econet                   */
#define AF_ATMSVC 20        /* ATM SVCs                       */
#define AF_RDS 21           /* RDS sockets                    */
#define AF_SNA 22           /* Linux SNA Project (nutters!)   */
#define AF_IRDA 23          /* IRDA sockets                   */
#define AF_PPPOX 24         /* PPPoX sockets                  */
#define AF_WANPIPE 25       /* Wanpipe API Sockets            */
#define AF_LLC 26           /* Linux LLC                      */
#define AF_IB 27            /* Native InfiniBand address      */
#define AF_MPLS 28          /* MPLS                           */
#define AF_CAN 29           /* Controller Area Network        */
#define AF_TIPC 30          /* TIPC sockets                   */
#define AF_BLUETOOTH 31     /* Bluetooth sockets             */
#define AF_IUCV 32          /* IUCV sockets                   */
#define AF_RXRPC 33         /* RxRPC sockets                  */
#define AF_ISDN 34          /* mISDN sockets                  */
#define AF_PHONET 35        /* Phonet sockets                 */
#define AF_IEEE802154 36    /* IEEE802154 sockets           */
#define AF_CAIF 37          /* CAIF sockets                   */
#define AF_ALG 38           /* Algorithm sockets              */
#define AF_NFC 39           /* NFC sockets                    */
#define AF_VSOCK 40         /* vSockets                       */
#define AF_KCM 41           /* Kernel Connection Multiplexor  */
#define AF_QIPCRTR 42       /* Qualcomm IPC Router            */
#define AF_SMC                                                                 \
    43            /* smc sockets: reserve number for                           \
                   * PF_SMC protocol family that                               \
                   * reuses AF_INET address family                             \
                   */
#define AF_XDP 44 /* XDP sockets          */

#define AF_MAX 45 /* For now.. */

#define PATH_MAX        4096	/* # chars in a path name including nul */

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member) ({          \
const typeof(((type *)0)->member)*__mptr = (ptr);    \
    (type *)((char *)__mptr - offsetof(type, member)); })

/**
 * list_entry - get the struct for this entry
 * @ptr: the &struct list_head pointer.
 * @type: the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
container_of(ptr, type, member)




void *memcpy1(void *__dest, __const void *__src, size_t __n)
{
	int i = 0;
	unsigned char *d = (unsigned char *)__dest, *s = (unsigned char *)__src;

	for (i = __n >> 3; i > 0; i--) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1 << 2) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1 << 1) {
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1)
		*d++ = *s++;

	return __dest;
}









#endif /* ifndef KERNEL_DEFS_H */