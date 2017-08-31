#include "firwall.h"

MODULE PARAM(work_mode,int,S_IRUGO);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Liu Qilin<1449675740@qq.com.com>");
MODULE_DESCRIPTION("firewall made with netfilter");
MODULE_ALIAS("A simple packet filter firewall");


static int packet_judge_ip(struct ip_node *ip,__be32 saddr,__be32 daddr)
{
	while(YES){
		if(ip->object == 's' && saddr >= ip->start && saddr <= ip->end)
			return NO;
		if(ip->object == 'd' && daddr >= ip->start && daddr <= ip->end)
			return NO;
		if(ip->next == NULL) 
			break;
		ip = ip->next;
	}	
	return YES;
}
static int packet_judge_port(struct port_node *port,unsigned int sport,unsigned dport)
{
	while(YES){
		if(port->object == 's' && port->portN == sport)
			return NO;
		if(port->object == 'd' && port->portN == dport)
			return NO;
		if(port->next == NULL)
			break;
		port = port->next;
	}
	return YES;
}
static int packet_judge_protocol(struct protocol_node *protocol,unsigned int protN)
{
	while(YES){
		if(protocol->protN == protN)
			return NO;
		if(protocol->next == NULL)
			break;
		protocol = protocol->next;
	}
	return YES;
}
static unsigned int hook_func_in(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff*))
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned int protN = iph->protocol;
	unsigned int sport,dport;
	if(protN == 6){
		struct tcphdr *tcp = tcp_hdr(skb);
		sport = ntohs(tcp->source);
		dport = ntohs(tcp->dest);
	}
	else if(protN == 17){
		struct tcphdr *udp = udp_hdr(skb);
		sport = ntohs(udp->source);
		dport = ntohs(udp->dest);	
	}
	__be32 saddr = ntohl(iph->saddr);
	__be32 daddr = ntohl(iph->daddr);
	switch(work_mode){		
		case MODE_FREE:	
			return NF_ACCEPT;
			break;
		case MODE_ALLOW_IN:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;
	
		case MODE_DENY_IN:
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;


		case MODE_ALLOW_IN_DENY_IN:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;

		case MODE_ALLOW_IN_ALLOW_OUT:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;

		case MODE_ALLOW_IN_DENY_OUT:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;

		case MODE_DENY_IN_ALLOW_OUT:
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;

		case MODE_DENY_IN_DENY_OUT:
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;

		case MODE_ALLOW_IN_OUT_DENY_IN:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;

		case MODE_ALLOW_IN_OUT_DENY_OUT:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;

		case MODE_ALLOW_IN_DENY_IN_OUT:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;

		case MODE_ALLOW_OUT_DENY_IN_OUT:
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;

		case MODE_ALLOW_IN_OUT_DENY_IN_OUT:
			if(packet_judge_ip(&ip_allow_in_head,saddr,daddr) && packet_judge_port(&port_allow_in_head,sport,dport) && packet_judge_protocol(&protocol_allow_in_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_in_head,saddr,daddr) && packet_judge_port(&port_deny_in_head,sport,dport) && packet_judge_protocol(&protocol_deny_in_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;		
			break;
		default: 
			return NF_ACCEPT;
			break;
	}
}
static unsigned int hook_func_out(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff*))
{
	struct iphdr *iph = ip_hdr(skb); 
	__be32 saddr = ntohl(iph->saddr);
	__be32 daddr = ntohl(iph->daddr);
	unsigned int protN = iph->protocol;
	unsigned int sport,dport;
	if(protN == 6){
		struct tcphdr *tcp = tcp_hdr(skb);
		sport = ntohs(tcp->source);
		dport = ntohs(tcp->dest);
	}
	else if(protN == 17){
		struct tcphdr *udp = udp_hdr(skb);
		unsigned int sport = ntohs(udp->source);
		unsigned int dport = ntohs(udp->dest);
	}
	switch(work_mode){		
		case MODE_FREE:	
			return NF_ACCEPT;
			break;

		case MODE_ALLOW_OUT:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;

		case MODE_DENY_OUT:
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN)){
				return NF_ACCEPT;
			}
			else
				return NF_DROP;
			break;

		case MODE_ALLOW_IN_ALLOW_OUT:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;

		case MODE_ALLOW_IN_DENY_OUT:
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;
			break;

		case MODE_DENY_IN_ALLOW_OUT:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;

		case MODE_DENY_IN_DENY_OUT:
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;
			break;

		case MODE_ALLOW_OUT_DENY_OUT:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;
			break;

		case MODE_ALLOW_IN_OUT_DENY_IN:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			break;

		case MODE_ALLOW_IN_OUT_DENY_OUT:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;
			break;

		case MODE_ALLOW_IN_DENY_IN_OUT:
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;
			break;

		case MODE_ALLOW_OUT_DENY_IN_OUT:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;
			break;

		case MODE_ALLOW_IN_OUT_DENY_IN_OUT:
			if(packet_judge_ip(&ip_allow_out_head,saddr,daddr) && packet_judge_port(&port_allow_out_head,sport,dport) && packet_judge_protocol(&protocol_allow_out_head,protN))
				return NF_DROP;
			else
				return NF_ACCEPT;
			if(packet_judge_ip(&ip_deny_out_head,saddr,daddr) && packet_judge_port(&port_deny_out_head,sport,dport) && packet_judge_protocol(&protocol_deny_out_head,protN))
				return NF_ACCEPT;
			else
				return NF_DROP;
			break;

		default:
			return NF_ACCEPT;	
			break;
	}		
}
void link_init()
{	
	(&ip_allow_in_head)->next = NULL;
	(&ip_deny_in_head)->next = NULL;
	(&ip_allow_out_head)->next = NULL;
	(&ip_deny_out_head)->next = NULL;

	(&port_allow_in_head)->next = NULL;
	(&port_deny_in_head)->next = NULL;
	(&port_allow_out_head)->next = NULL;
	(&port_deny_out_head)->next = NULL;
	
	(&protocol_allow_in_head)->next = NULL;
	(&protocol_deny_in_head)->next = NULL;
	(&protocol_allow_out_head)->next = NULL;
	(&protocol_deny_out_head)->next = NULL;
}

static int ip_to_unsigned(const char *str,struct ip_node *ip)
{
	char ipd[4][4];
	int i=0,k=0,j=0;
	for(i=0;str[i]!='\0';i++){
		ipd[j][k] = str[i];
		if(str[i] == '.'){
			ipd[j][k] = '\0';
			k = 0;
			j++;
		}
		else k++;
		if(j>3)	return NO;
	}
	ipd[3][k] = '\0';
	short int a[4];
	for(i=0;i<4;i++){
		if(ipd[i][0] != '*'){
			a[i] = (short)simple_strtol(ipd[i],NULL,0);
			if(a[i]<0 || a[i]>255) return NO;
		}
		else	break;
	}
	switch(i){
		case 4:
			ip->start = ip->end = (a[0]<<24)+(a[1]<<16)+(a[2]<<8)+a[3];
			break;
		case 3:
			ip->start = (a[0]<<24)+(a[1]<<16)+(a[2]<<8);
			ip->end = ip->start+(1<<8)-1;
			break;
		case 2:
			ip->start = (a[0]<<24)+(a[1]<<16);
			ip->end = ip->start+(1<<16)-1;
			break;
		case 1:
			ip->start = (a[0]<<24);
			ip->end = ip->start+(1<<24)-1;
			break;
		default:
			ip->start = 0;
			ip->end = (1<<32)-1;
			break;
			
	}
	return YES;
}

static int port_to_unsigned(const char *str,struct port_node *port)
{
	int i = 0;
	unsigned int temp = 0;
	unsigned int num = 0;
	for(i=0;str[i]!='\0';i++){
		temp = str[i] - '0';
		num = num*10 + temp;
	}
	if(num > 4096)
		return NO;
	port->portN = num;
	return YES;
}

static int protocol_to_unsigned(const char *str,struct protocol_node *protocol)
{
	if(str[0]=='i'&&str[1]=='c'&&str[2]=='m'&&str[3]=='p'&&str[4]=='\0')
		protocol->protN = 1;
	else if(str[0]=='i'&&str[1]=='g'&&str[2]=='m'&&str[3]=='p'&&str[4]=='\0'	)
		protocol->protN = 2;
	else if(str[0]=='t'&&str[1]=='c'&&str[2]=='p'&&str[3]=='\0')
		protocol->protN = 6;
	else if(str[0]=='u'&&str[1]=='d'&&str[2]=='p'&&str[3]=='\0')
		protocol->protN = 17;
	else 
		return NO;
	return YES;
}

static void ip_judge(struct ip_node *ip,int judge)
{
	switch(judge){
		case ALLOW_IN:
			ip->next = (&ip_allow_in_head)->next;
			(&ip_allow_in_head)->next = ip;
			break;
		case DENY_IN:
			ip->next = (&ip_deny_in_head)->next;
			(&ip_deny_in_head)->next = ip;
			break;
		case ALLOW_OUT:
			ip->next = (&ip_allow_out_head)->next;
			(&ip_allow_out_head)->next = ip;
			break;
		case DENY_OUT:
			ip->next = (&ip_deny_out_head)->next;
			(&ip_deny_out_head)->next = ip;
			break;
		default: break;
	}
}

static void port_judge(struct port_node *port,int judge)
{
	
	switch(judge){
		case ALLOW_IN:
			port->next = (&port_allow_in_head)->next;
			(&port_allow_in_head)->next = port;
			break;
		case DENY_IN:
			port->next = (&port_deny_in_head)->next;
			(&port_deny_in_head)->next = port;
			break;
		case ALLOW_OUT:
			port->next = (&port_allow_out_head)->next;
			(&port_allow_out_head)->next = port;
			break;
		case DENY_OUT:
			port->next = (&port_deny_out_head)->next;
			(&port_deny_out_head)->next = port;
			break;
		default: break;
	}
}

static void protocol_judge(struct protocol_node *protocol,int judge)
{
	switch(judge){
		case ALLOW_IN:
			protocol->next = (&protocol_allow_in_head)->next;
			(&protocol_allow_in_head)->next = protocol;
			break;
		case DENY_IN:
			protocol->next = (&protocol_deny_in_head)->next;
			(&protocol_deny_in_head)->next = protocol;
			break;
		case ALLOW_OUT:
			protocol->next = (&protocol_allow_out_head)->next;
			(&protocol_allow_out_head)->next = protocol;
			break;
		case DENY_OUT:
			protocol->next = (&protocol_deny_out_head)->next;
			(&protocol_deny_out_head)->next = protocol;
			break;
		default: break;
	}
}
//static void open_file_data(char *dir,struct ip_node *ip,struct port_node *port,struct protocol_node *protocol)
static void open_file_data(char *dir,int judge)
{
	struct file *fp = NULL;
	mm_segment_t fs;
	char str[str_len_max];	
	char saddr[ip_len_max];
	char daddr[ip_len_max];
	char sport[port_len_max];
	char dport[port_len_max];
	char proto[protocol_len_max];
	int i = 0;
	int j = 0;
	struct ip_node *ip = NULL;
	struct port_node *port = NULL;
	struct protocol_node *protocol = NULL;
       
	fp = filp_open(dir,O_RDONLY,0);
	if(IS_ERR(fp)){
		printk(KERN_EMERG "write the file is wrong!\n");
		return;
	}
	fs = get_fs();
	set_fs(KERNEL_DS);
	while((fp->f_op->read(fp,&str[i],1,&fp->f_pos)) == 1){
		if(str[i] == '\n'){
			str[i] = '\0';
			i = 0;
			if(str[0]=='s'&&str[1]=='a'&&str[2]=='d'&&str[3]=='d'&&str[4]=='r'){
				ip = (struct ip_node *)kmalloc(sizeof(struct ip_node),GFP_ATOMIC);
				for(j=0;str[j+6]!='\0';j++)
					saddr[j] = str[j+6];
				saddr[j] = '\0';
				if(ip_to_unsigned(saddr,ip)){
					ip->object = 's';
					ip_judge(ip,judge);
				}
			}
			if(str[0]=='d'&&str[1]=='a'&&str[2]=='d'&&str[3]=='d'&&str[4]=='r'){
				ip = (struct ip_node *)kmalloc(sizeof(struct ip_node),GFP_ATOMIC);
				for(j=0;str[j+6]!='\0';j++)
					daddr[j] = str[j+6];
				daddr[j] = '\0';
				if(ip_to_unsigned(daddr,ip)){
					ip->object = 'd';
					ip_judge(ip,judge);
				}
			}		
			if(str[0]=='s'&&str[1]=='p'&&str[2]=='o'&&str[3]=='r'&&str[4]=='t'){
				port = (struct port_node *)kmalloc(sizeof(struct port_node),GFP_ATOMIC);
				for(j=0;str[j+6]!='\0';j++)
					sport[j] = str[j+6];
				sport[j] = '\0';
				if(port_to_unsigned(sport,port)){
					port->object = 's';
					port_judge(port,judge);
				}
			}
			if(str[0]=='d'&&str[1]=='p'&&str[2]=='o'&&str[3]=='r'&&str[4]=='t'){
				port = (struct port_node *)kmalloc(sizeof(struct port_node),GFP_ATOMIC);
				for(j=0;str[j+6]!='\0';j++)
					dport[j] = str[j+6];
				dport[j] = '\0';
				if(port_to_unsigned(dport,port)){
					port->object = 'd';
					port_judge(port,judge);
				}
			}
			if(str[0]=='p'&&str[1]=='r'&&str[2]=='o'&&str[3]=='t'&&str[4]=='o'&&str[5]=='c'&&str[6]=='o'&&str[7]=='l'){
				protocol = (struct protocol_node *)kmalloc(sizeof(struct protocol_node),GFP_ATOMIC);
				for(j=0;str[j+9]!='\0';j++)
					proto[j] = str[j+9];
				proto[j] = '\0';
				if(protocol_to_unsigned(proto,protocol)){
					protocol_judge(protocol,judge);
				}
			}
		}
		else if(str[i] != ' ') i++;
	}
	filp_close(fp,NULL);
	set_fs(fs);
	return;
}

void open_file(int flag)
{
	if(flag == MODE_FREE)
		return;

	if(flag == MODE_ALLOW_IN)
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
	if(flag == MODE_DENY_IN)
		open_file_data(DENY_IN_FILE,DENY_IN);
	if(flag == MODE_ALLOW_OUT)
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
	if(flag == MODE_DENY_OUT)
		open_file_data(DENY_OUT_FILE,DENY_OUT);

	if(flag == MODE_ALLOW_IN_DENY_IN){
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
		open_file_data(DENY_IN_FILE,DENY_IN);
	}
	if(flag == MODE_ALLOW_IN_ALLOW_OUT){
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
	}
	if(flag == MODE_ALLOW_IN_DENY_OUT){
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
		open_file_data(DENY_OUT_FILE,DENY_OUT);
	}
	if(flag == MODE_DENY_IN_ALLOW_OUT){
		open_file_data(DENY_IN_FILE,DENY_IN);
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
	}
	if(flag == MODE_DENY_IN_DENY_OUT){
		open_file_data(DENY_IN_FILE,DENY_IN);
		open_file_data(DENY_OUT_FILE,DENY_OUT);
	}
	if(flag == MODE_ALLOW_OUT_DENY_OUT){
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
		open_file_data(DENY_OUT_FILE,DENY_OUT);
	}

	if(flag == MODE_ALLOW_IN_OUT_DENY_IN){
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
		open_file_data(DENY_IN_FILE,DENY_IN);
	}
	if(flag == MODE_ALLOW_IN_OUT_DENY_OUT){
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
		open_file_data(DENY_OUT_FILE,DENY_OUT);
	}
	if(flag == MODE_ALLOW_IN_DENY_IN_OUT){	
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
		open_file_data(DENY_IN_FILE,DENY_IN);
		open_file_data(DENY_OUT_FILE,DENY_OUT);
	}
	if(flag == MODE_ALLOW_OUT_DENY_IN_OUT){
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
		open_file_data(DENY_IN_FILE,DENY_IN);
		open_file_data(DENY_OUT_FILE,DENY_OUT);
	}

	if(flag == MODE_ALLOW_IN_OUT_DENY_IN_OUT){
		open_file_data(ALLOW_IN_FILE,ALLOW_IN);
		open_file_data(ALLOW_OUT_FILE,ALLOW_OUT);
		open_file_data(DENY_IN_FILE,DENY_IN);
		open_file_data(DENY_OUT_FILE,DENY_OUT);
	}
	return;
}

static struct nf_hook_ops netfilter[]=
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
};

//static int __init myhook_init(void)
static int myhook_init(void)
{
	link_init();
	switch(work_mode){		
		case MODE_FREE:	break;
		case MODE_ALLOW_IN:
			open_file(MODE_ALLOW_IN);
			break;
		case MODE_DENY_IN:
			open_file(MODE_DENY_IN);
			break;
		case MODE_ALLOW_OUT:
			open_file(MODE_ALLOW_OUT);
			break;
		case MODE_DENY_OUT:
			open_file(MODE_DENY_OUT);
			break;

		case MODE_ALLOW_IN_DENY_IN:
			open_file(MODE_ALLOW_IN_DENY_IN);
			break;
		case MODE_ALLOW_IN_ALLOW_OUT:
			open_file(MODE_ALLOW_IN_ALLOW_OUT);
			break;
		case MODE_ALLOW_IN_DENY_OUT:
			open_file(MODE_ALLOW_IN_DENY_OUT);
			break;
		case MODE_DENY_IN_ALLOW_OUT:
			open_file(MODE_DENY_IN_ALLOW_OUT);
			break;
		case MODE_DENY_IN_DENY_OUT:
			open_file(MODE_DENY_IN_DENY_OUT);
			break;
		case MODE_ALLOW_OUT_DENY_OUT:
			open_file(MODE_ALLOW_OUT_DENY_OUT);
			break;

		case MODE_ALLOW_IN_OUT_DENY_IN:
			open_file(MODE_ALLOW_IN_OUT_DENY_IN);
			break;
		case MODE_ALLOW_IN_OUT_DENY_OUT:
			open_file(MODE_ALLOW_IN_OUT_DENY_OUT);
			break;
		case MODE_ALLOW_IN_DENY_IN_OUT:
			open_file(MODE_ALLOW_IN_DENY_IN_OUT);
			break;
		case MODE_ALLOW_OUT_DENY_IN_OUT:
			open_file(MODE_ALLOW_OUT_DENY_IN_OUT);
			break;

		case MODE_ALLOW_IN_OUT_DENY_IN_OUT:
			open_file(MODE_ALLOW_IN_OUT_DENY_IN_OUT);
			break;
		default:
			break;
	}
	nf_register_hook(&netfilter[0]);
	nf_register_hook(&netfilter[1]);
	return 0;
}

//static void __exit myhook_fini(void)
static void myhook_fini(void)
{
	/*kfree(&ip_allow_in_head);
	kfree(&ip_allow_out_head);
	kfree(&ip_deny_in_head);
	kfree(&ip_deny_out_head);

	kfree(&port_allow_in_head);
	kfree(&port_allow_out_head);
	kfree(&port_deny_in_head);
	kfree(&port_deny_out_head);

	kfree(&protocol_allow_in_head);
	kfree(&protocol_allow_out_head);
	kfree(&protocol_deny_in_head);
	kfree(&protocol_deny_out_head);*/

	nf_unregister_hook(&netfilter[0]);
	nf_unregister_hook(&netfilter[1]);
}
module_init(myhook_init);
module_exit(myhook_fini);
