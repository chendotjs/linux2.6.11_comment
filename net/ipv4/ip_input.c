/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Version:	$Id: ip_input.c,v 1.55 2002/01/12 07:39:45 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *  
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single 
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/config.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *	SNMP management statistics
 */
/**
 * IP协议统计计数。
 */
DEFINE_SNMP_STAT(struct ipstats_mib, ip_statistics);

/*
 *	Process Router Attention IP option
 */ 
int ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = skb->nh.iph->protocol;
	struct sock *last = NULL;

	read_lock(&ip_ra_lock);
	for (ra = ip_ra_chain; ra; ra = ra->next) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == skb->dev->ifindex)) {
			if (skb->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
				skb = ip_defrag(skb, IP_DEFRAG_CALL_RA_CHAIN);
				if (skb == NULL) {
					read_unlock(&ip_ra_lock);
					return 1;
				}
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		read_unlock(&ip_ra_lock);
		return 1;
	}
	read_unlock(&ip_ra_lock);
	return 0;
}

/**
 * L3到L4的传递:主要工作是根据输入IP包报头的"协议"字段找出正确的协议处理函数，然后把该包交给该处理函数。
 * 同时，ip_local_deliver_finish必须处理Raw IP。此外，如果有配置安全策略，该函数也要施加安全检查。
 */
static inline int ip_local_deliver_finish(struct sk_buff *skb)
{
	/**
	 * skb->nh是在netif_receive_skb中初始化，来指向IP报头的开端。
	 */
	int ihl = skb->nh.iph->ihl*4;

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_local_deliver(skb);
#endif /*CONFIG_NETFILTER_DEBUG*/

	/**
	 * 此时内核不再需要IP报头了，因为IP层的事情已经做完，而且包也要传给下一个较高层了。
	 * 因此，这里所示的__skb_pull调用会把包的数据部分缩小来忽略L3报头
	 */
	__skb_pull(skb, ihl);

	/* Free reference early: we don't need it any more, and it may
           hold ip_conntrack module loaded indefinitely. */
	nf_reset(skb);

        /* Point into the IP datagram, just past the header. */
		/**
		 * L4层起始地址。
		 */
        skb->h.raw = skb->data;

	rcu_read_lock();
	{
		/* Note: See raw.c and net/raw.h, RAWV4_HTABLE_SIZE==MAX_INET_PROTOS */
		/**
		 * 协议ID是从skb->nh.iph->protocol变量（指向IP报头的"协议"字段）取出的。
		 */
		int protocol = skb->nh.iph->protocol;
		int hash;
		struct sock *raw_sk;
		struct net_protocol *ipprot;

	resubmit:
		hash = protocol & (MAX_INET_PROTOS - 1);
		/**
		 * 协议对应的第一个原始套口
		 */
		raw_sk = sk_head(&raw_v4_htable[hash]);

		/* If there maybe a raw socket we must check - if not we
		 * don't care less
		 */
		if (raw_sk)/* 存在原始套口，调用raw_v4_input处理它们。raw_v4_input会复制数据包。 */
			raw_v4_input(skb, skb->nh.iph, hash);

		/**
		 * 查找内核中注册的协议处理函数。
		 */
		if ((ipprot = rcu_dereference(inet_protos[hash])) != NULL) {
			int ret;

			/**
			 * 如果此L4层处理函数需要检查IPSEC并且没有通过检查，就释放包并退出。
			 */
			if (!ipprot->no_policy &&
			    !xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				kfree_skb(skb);
				goto out;
			}
			/**
			 * 调用L4层处理函数。
			 */
			ret = ipprot->handler(skb);
			if (ret < 0) {/* 这里应该是处理IPSEC */
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(IPSTATS_MIB_INDELIVERS);
		} else {
			if (!raw_sk) {/* 没有L4层处理函数，同时没有对应的原始套接字处理该包。 */
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {/* 如果IPSEC允许对该包发送ICMP，则回送ICMP消息。 */
					IP_INC_STATS_BH(IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
			} else
				IP_INC_STATS_BH(IPSTATS_MIB_INDELIVERS);
			kfree_skb(skb);/* 释放包。 */
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */ 
/**
 * IPV4处理本地报文接收。
 */
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	/**
	 * 和转发（重组基本上可以忽略）相反的是，本地传递必须做很多工作来处理重组工作。
	 * 在MF标志或者OFFSET不为0，都表示是一个分片。
	 */
	if (skb->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
		/**
		 * 重组工作是在ip_defrag函数内进行的。
		 * 当ip_defrag完成重组工作时，会返回一个指向原有包的指针，但是，如果包还不完整，就返回NULL。
		 */
		skb = ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER);
		if (!skb)
			return 0;
	}

	/**
	 * 如果通过了netfilter的检查，包被ip_local_deliver_finish传递给上层函数处理。
	 */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_IN, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

/**
 * ip_recv的主要处理函数。此时，包已经通过了基本的健康检查，以及防火墙审查。本函数的主要工作有澹
 *		决定包是否必须本地传递或者转发。如果需要转发，就必须找到出口设备和下一个跳点。
 *		分析和处理一些IP选项。然而，关碍所有IP选项都在此处理。
 */
static inline int ip_rcv_finish(struct sk_buff *skb)
{
	/**
	 * skb->nh字段是在netif_receive_skb里初始化的。
	 * 当时，还不知道L3协议，所以会使用nh.raw做初始化。现在，此函数可以取得指向IP报头的指针了。
	 */
	struct net_device *dev = skb->dev;
	struct iphdr *iph = skb->nh.iph;

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */ 
	/**
	 * skb->dst可能包含包通往其目的地的路由信息。
	 * 如果没有得知该消息，此函数会询问路由子系统该把包传送到哪儿.
	 * 注:当包进入此函数时，如果是环回设备，dst应该已经准备好了。
	 */
	if (skb->dst == NULL) {
		/**
		 * 如果路由子系统说目的地无法抵达，则该包会被丢弃。
		 */
		if (ip_route_input(skb, iph->daddr, iph->saddr, iph->tos, dev))
			goto drop; 
	}

#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * 更新一些QoS所用的统计数据。
	 */
	if (skb->dst->tclassid) {
		struct ip_rt_acct *st = ip_rt_acct + 256*smp_processor_id();
		u32 idx = skb->dst->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes+=skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes+=skb->len;
	}
#endif

	/**
	 * 当IP报头的长度大于20字节（5*32位），表示有一些选项需要处理。
	 */
	if (iph->ihl > 5) {
		struct ip_options *opt;

		/* It looks as overkill, because not all
		   IP options require packet mangling.
		   But it is the easiest for now, especially taking
		   into account that combination of IP options
		   and running sniffer is extremely rare condition.
		                                      --ANK (980813)
		*/

		/**
		 * skb_cow被调用。如果缓冲区和别人共享，就会做出缓冲区的副本.
		 * 对缓冲区具有排他拥有权是必要的，因为我们要处理那些选项，而且有可能需要修改IP报头。
		 */
		if (skb_cow(skb, skb_headroom(skb))) {
			IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
			goto drop;
		}
		iph = skb->nh.iph;

		/**
		 * ip_option_compile用于解读报头中所携带的IP选项。
		 * IP层用cb字段存储IP报头选项分析结果以及其他一些数据（如分段相关的信息）。
		 * 此结果储存在一个struct inet_skb_parm类型的数据结构（定义在include/net/ip.h中），而且可以由宏IPCB存取。
		 */
		if (ip_options_compile(NULL, skb))
			goto inhdr_error;/* 如果有任何错误的选项，包就会被丢弃。而一条特殊的ICMP消息就会送回给传送者来告知所发生的问题。 */

		/**
		 * ip_options_compile将选项保存在skb->cb中，此处取出选项，进行处理。
		 */
		opt = &(IPCB(skb)->opt);
		/**
		 * 处理IP源路由
		 */
		if (opt->srr) {
			struct in_device *in_dev = in_dev_get(dev);
			if (in_dev) {
				/**
				 * 配置不允许进行源路由。
				 */
				if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
					if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
						printk(KERN_INFO "source route option %u.%u.%u.%u -> %u.%u.%u.%u\n",
						       NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
					in_dev_put(in_dev);
					goto drop;
				}
				in_dev_put(in_dev);
			}
			/**
			 * ip_options_rcv_srr根据源路由选项，确定使用哪个设备把该包转发至来源地路由列表中的下一个跳点。
			 * ip_options_rcv_srr还得考虑"下一跳点"是本地主机的一个接口的可能性。如果发生这种事情，此函数会把该IP地址写入IP报头的目的地IP地址，然后继续检查来源地路由列表中的下一个地址（如果有的话）。在程序中，这被称为"超快循环转发"。
			 * Ip_options_rcv_srr会持续浏览IP报头来源地址路由选项区块中的下一个跳点列表。直到其找到一个不是主机本地的IP地址。正常的说，该列表中不会有一个以上的本地IP地址。然而，有一个以上也是合法的。
			 */
			if (ip_options_rcv_srr(skb))
				goto drop;
		}
	}

	/**
	 * dst_input实际上会调用存储于skb缓冲区的dst字段的函数。
	 * skb->dst的初始化不是在ip_rcv_finish的开端，就是在ip_options_rcv_srr的尾端。
	 * skb->dst->input会设成ip_local_deliver或ip_forward，这取决于包的目的地址。
	 * 因此，调用dst_input时，就可以完成包的处理。
	 */
	return dst_input(skb);

inhdr_error:
	IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
drop:
        kfree_skb(skb);
        return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */ 
/**
 * IPV4入包主处理函数。
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
{
	struct iphdr *iph;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	/**
	 * 数据帧的L2目的地址和接收接口的地址不同时，skb->pkt_type就会被设置成PACKET_OTHERHOST。通常这些包会被NIC本身丢弃。
	 * 然而，如果该接口已经进入混杂模式，无论目的地L2地址为何，都会接收所有包并将其转给较高层。
	 * 内核会调用那些要求要存取所有包的嗅探器。但是ip_rcv和传给其他地址的入包无关，而只会简单的丢弃它们。
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	IP_INC_STATS_BH(IPSTATS_MIB_INRECEIVES);

	/**
	 * Skb_share_check会检查包的引用计数是否大于1，大于1则表示内核的其他部分拥有对该缓冲区的引用。
	 * 如果引用计数大于1，就会自己建议一份缓冲区副本。
	 */
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		/**
		 * 由于内存不足而失败。
		 */
		IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	/**
	 * pskb_may_pull的工作是确保skb->data所区域包含的数据区至少和IP报头一样大，因为每个IP包（包括片段）必须包含一个完整的IP报头。
	 * 缺失的部分就会从存储在skb_shinfo(skb)->frags里的数据片段复制过来。
	 */
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	/**
	 * 函数必须再次初始化iph，因为pskb_may_pull可以改变缓冲区结构。
	 */
	iph = skb->nh.iph;

	/*
	 *	RFC1122: 3.1.2.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	/**
	 * 接着对IP报头做一些健康检查。
	 * 基本IP报头的尺寸是20字节，因为存储在报头内的尺寸是以32位（4字节）的倍数表示，如果其值小于5，则表示有错误。
	 * 后检查协议版本号是为了效率原因。
	 */
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error; 

	/**
	 * 重复先前做过的相同检查，只不过这一次使用的是完整的IP报头尺寸（包括选项）。
	 * 如果IP报头声明了iph->ihl的尺寸，则包应该至少和iph->ihl一样长。
	 * 这项检查一直到现在才做，是因为此函数必须先确定基本报头（即不含选项的报头）没有被截断。
	 * 而且从中读取的东西已经经过基本健康检查。
	 */
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = skb->nh.iph;

	/**
	 * 此函数必须计算校验和，然后看看是否和报头中所携带的吻合。如果不吻合，该包就会被丢弃。
	 */
	if (ip_fast_csum((u8 *)iph, iph->ihl) != 0)
		goto inhdr_error; 

	{
		__u32 len = ntohs(iph->tot_len); 
		/**
		 * 缓冲区（即已接收的包）长度大于或者等于IP报头中记录的长度。
		 *		这是由于L2协议（如ethernet）会填充有效负载，所以，在IP有效负载之后可能有多余的字节.
		 * 包的尺寸至少和IP报头的尺寸一样大。
		 *		这是由于IP报头不能分段的事实。因此，每个IP片段必须至少包含一个IP报头。
		 */
		if (skb->len < len || len < (iph->ihl<<2))
			goto inhdr_error;

		/* Our transport medium may have padded the buffer out. Now we know it
		 * is IP we can trim to the true length of the frame.
		 * Note this now means skb->len holds ntohs(iph->tot_len).
		 */
		/**
		 * L2层填充了一些数据报内容。
		 */
		if (skb->len > len) {
			/**
			 * 截断L2层填充的数据报内容。
			 */
			__pskb_trim(skb, len);
			/**
			 * 由于报文内容发生了改变，而硬件计算的校验和可能是计算了填充的报文，此时应当失效。
			 */
			if (skb->ip_summed == CHECKSUM_HW)
				skb->ip_summed = CHECKSUM_NONE;
		}
	}

	/**
	 * 如果通过了防火墙的检测，那么就调用ip_rcv_finish进行真正的路由决策。
	 */
	return NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, dev, NULL,
		       ip_rcv_finish);

inhdr_error:
	IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
drop:
        kfree_skb(skb);
out:
        return NET_RX_DROP;
}

EXPORT_SYMBOL(ip_rcv);
EXPORT_SYMBOL(ip_statistics);
