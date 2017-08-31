#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include<asm/system.h>
#include<linux/module.h>
#include<linux/types.h>
#include<linux/kernel.h>
#include<linux/string.h>
#include<linux/net.h>
#include<linux/socket.h>
#include<linux/sockios.h>
#include<linux/in.h>
#include<linux/inet.h>
#include<linux/moduleparam.h>

#include<net/ip.h>
#include<net/protocol.h>
#include<linux/skbuff.h>
#include<net/sock.h>
#include<net/icmp.h>
#include<net/raw.h>
#include<net/checksum.h>
#include<linux/netfilter_ipv4.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/igmp.h>
#include<linux/slab.h>
#include<linux/fs.h>
#include<linux/mm.h>
#include<linux/uaccess.h>

#define YES 1
#define NO 0
#define str_len_max 24
#define ip_len_max 20
#define port_len_max 8
#define protocol_len_max 8

#define ALLOW_IN_FILE "/etc/my_firwall/allow_in"
#define DENY_IN_FILE "/etc/my_firwall/deny_in"
#define ALLOW_OUT_FILE "/etc/my_firwall/allow_out"
#define DENY_OUT_FILE "/etc/my_firwall/deny_out"

#define ALLOW_IN 1
#define DENY_IN 2
#define ALLOW_OUT 3
#define DENY_OUT 4

#define MODE_FREE 0
#define MODE_ALLOW_IN 1
#define MODE_DENY_IN 2
#define MODE_ALLOW_OUT 3
#define MODE_DENY_OUT 4

#define MODE_ALLOW_IN_DENY_IN 5
#define MODE_ALLOW_IN_ALLOW_OUT 6
#define MODE_ALLOW_IN_DENY_OUT 7
#define MODE_DENY_IN_ALLOW_OUT 8
#define MODE_DENY_IN_DENY_OUT 9
#define MODE_ALLOW_OUT_DENY_OUT 10

#define MODE_ALLOW_IN_OUT_DENY_IN 11
#define MODE_ALLOW_IN_OUT_DENY_OUT 12
#define MODE_ALLOW_IN_DENY_IN_OUT 13
#define MODE_ALLOW_OUT_DENY_IN_OUT 14

#define MODE_ALLOW_IN_OUT_DENY_IN_OUT 15
struct ip_node{
	char object;
	__be32 start;
	__be32 end;
	struct ip_node * next;
};

struct port_node{
	char object;
	unsigned int portN;
	struct port_node * next;
};

struct protocol_node{
	unsigned int protN;
	struct protocol_node * next; 
};

struct ip_node ip_allow_in_head;
struct ip_node ip_deny_in_head;
struct ip_node ip_allow_out_head;
struct ip_node ip_deny_out_head;

struct port_node port_allow_in_head;
struct port_node port_deny_in_head;
struct port_node port_allow_out_head;
struct port_node port_deny_out_head;

struct protocol_node protocol_allow_in_head;
struct protocol_node protocol_deny_in_head;
struct protocol_node protocol_allow_out_head;
struct protocol_node protocol_deny_out_head;

/*static struct nf_hook_ops netfilter[]=
{
{
	.hook = hook_func_in,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
},
{
	.hook = hook_func_out,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
}	
};*/
