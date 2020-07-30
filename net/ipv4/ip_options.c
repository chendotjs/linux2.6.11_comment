/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The options processing module for ip.c
 *
 * Version:	$Id: ip_options.c,v 1.21 2001/09/01 00:31:50 davem Exp $
 *
 * Authors:	A.N.Kuznetsov
 *		
 */

#include <linux/module.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>

/* 
 * Write options to IP header, record destination address to
 * source route option, address of outgoing interface
 * (we should already know it, so that this  function is allowed be
 * called only after routing decision) and timestamp,
 * if we originate this datagram.
 *
 * daddr is real destination address, next hop is recorded in IP header.
 * saddr is address of outgoing interface.
 */
/**
 * 对IP报头中专属的那些选项部分做初始化（根据输入的ip_options结构）。传输本地产生的包时，就会用到此函数。
 */
void ip_options_build(struct sk_buff * skb, struct ip_options * opt,
			    u32 daddr, struct rtable *rt, int is_frag) 
{
	unsigned char * iph = skb->nh.raw;

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
	opt = &(IPCB(skb)->opt);
	opt->is_data = 0;

	if (opt->srr)
		memcpy(iph+opt->srr+iph[opt->srr+1]-4, &daddr, 4);

	if (!is_frag) {
		if (opt->rr_needaddr)
			ip_rt_get_source(iph+opt->rr+iph[opt->rr+2]-5, rt);
		if (opt->ts_needaddr)
			ip_rt_get_source(iph+opt->ts+iph[opt->ts+2]-9, rt);
		if (opt->ts_needtime) {
			struct timeval tv;
			__u32 midtime;
			do_gettimeofday(&tv);
			midtime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
			memcpy(iph+opt->ts+iph[opt->ts+2]-5, &midtime, 4);
		}
		return;
	}
	if (opt->rr) {
		memset(iph+opt->rr, IPOPT_NOP, iph[opt->rr+1]);
		opt->rr = 0;
		opt->rr_needaddr = 0;
	}
	if (opt->ts) {
		memset(iph+opt->ts, IPOPT_NOP, iph[opt->ts+1]);
		opt->ts = 0;
		opt->ts_needaddr = opt->ts_needtime = 0;
	}
}

/* 
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */
/**
 * 指定入包及IP选项后，此函数就可建立用于回复传送者的IP选项。
 *		 回复ICMP入包请求的icmp_replay。
 *	 	 当IP入包符合产生ICMP消息需求时的icmp_send。
 *		 IP层所提供的通用函数ip_send_reply（以回复IP入包）。
 *		 存储入SYN段的选项的TCP。
 */
int ip_options_echo(struct ip_options * dopt, struct sk_buff * skb) 
{
	struct ip_options *sopt;
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;
	u32	daddr;

	memset(dopt, 0, sizeof(struct ip_options));

	dopt->is_data = 1;

	sopt = &(IPCB(skb)->opt);

	if (sopt->optlen == 0) {
		dopt->optlen = 0;
		return 0;
	}

	sptr = skb->nh.raw;
	dptr = dopt->__data;

	if (skb->dst)
		daddr = ((struct rtable*)skb->dst)->rt_spec_dst;
	else
		daddr = skb->nh.iph->daddr;

	if (sopt->rr) {
		optlen  = sptr[sopt->rr+1];
		soffset = sptr[sopt->rr+2];
		dopt->rr = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->rr, optlen);
		if (sopt->rr_needaddr && soffset <= optlen) {
			if (soffset + 3 > optlen)
				return -EINVAL;
			dptr[2] = soffset + 4;
			dopt->rr_needaddr = 1;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->ts) {
		optlen = sptr[sopt->ts+1];
		soffset = sptr[sopt->ts+2];
		dopt->ts = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->ts, optlen);
		if (soffset <= optlen) {
			if (sopt->ts_needaddr) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				dopt->ts_needaddr = 1;
				soffset += 4;
			}
			if (sopt->ts_needtime) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
					dopt->ts_needtime = 1;
					soffset += 4;
				} else {
					dopt->ts_needtime = 0;

					if (soffset + 8 <= optlen) {
						__u32 addr;

						memcpy(&addr, sptr+soffset-1, 4);
						if (inet_addr_type(addr) != RTN_LOCAL) {
							dopt->ts_needtime = 1;
							soffset += 8;
						}
					}
				}
			}
			dptr[2] = soffset;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->srr) {
		unsigned char * start = sptr+sopt->srr;
		u32 faddr;

		optlen  = start[1];
		soffset = start[2];
		doffset = 0;
		if (soffset > optlen)
			soffset = optlen + 1;
		soffset -= 4;
		if (soffset > 3) {
			memcpy(&faddr, &start[soffset-1], 4);
			for (soffset-=4, doffset=4; soffset > 3; soffset-=4, doffset+=4)
				memcpy(&dptr[doffset-1], &start[soffset-1], 4);
			/*
			 * RFC1812 requires to fix illegal source routes.
			 */
			if (memcmp(&skb->nh.iph->saddr, &start[soffset+3], 4) == 0)
				doffset -= 4;
		}
		if (doffset > 3) {
			memcpy(&start[doffset-1], &daddr, 4);
			dopt->faddr = faddr;
			dptr[0] = start[0];
			dptr[1] = doffset+3;
			dptr[2] = 4;
			dptr += doffset+3;
			dopt->srr = dopt->optlen + sizeof(struct iphdr);
			dopt->optlen += doffset+3;
			dopt->is_strictroute = sopt->is_strictroute;
		}
	}
	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}

/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */
/**
 * 因为第一个片段是唯一继承原有包的所有选项的片段，所以，其报头的尺寸应大于或等于后续片段的尺寸。
 * LINUX让所有片段都保持相同的报头尺寸，让分段流程更为简单有效。
 * 其做法是拷贝原有报头及其所有选项，然后，除了第一个片段以外，对其他所有片段都以空选项覆盖那些不需要重复的选项（也就是IPOPT_COPY没设定的选项），然后清掉和其相关的ip_options标志（如ts_needaddr）。
 * 本函数修改第一个片段的IP报头，使其可以被后续片段循环利用。
 */
void ip_options_fragment(struct sk_buff * skb) 
{
	unsigned char * optptr = skb->nh.raw;
	struct ip_options * opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen<2 || optlen>l)
		  return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
	return;
}

/*
 * Verify options and fill pointers in struct options.
 * Caller should clear *opt, and set opt->data.
 * If opt == NULL, then skb->data should point to IP header.
 */
/**
 * 分析IP报头中的一些选项，然后相应的对一个ip_options结构的实例做初始化。
 * 两个输入参数的值会让函数知道自身是在什么情况下被调用的：
 *		入包：skb不为NULL，opt为NULL。
 * 		包正被传输：skb为NULL，opt非空。
 */
int ip_options_compile(struct ip_options * opt, struct sk_buff * skb)
{
	int l;
	unsigned char * iph;
	unsigned char * optptr;
	int optlen;
	unsigned char * pp_ptr = NULL;
	struct rtable *rt = skb ? (struct rtable*)skb->dst : NULL;

	/**
	 * opt为空，说明是入包。
	 */
	if (!opt) {
		opt = &(IPCB(skb)->opt);
		memset(opt, 0, sizeof(struct ip_options));
		/**
		 * 从入包中取IP头。
		 */
		iph = skb->nh.raw;
		opt->optlen = ((struct iphdr *)iph)->ihl*4 - sizeof(struct iphdr);
		/**
		 * 选项起始地址。。
		 */
		optptr = iph + sizeof(struct iphdr);
		opt->is_data = 0;
	} else {
		/**
		 * 从opt中取出选项起始地址和包头。
		 */
		optptr = opt->is_data ? opt->__data : (unsigned char*)&(skb->nh.iph[1]);
		iph = optptr - sizeof(struct iphdr);
	}

	/**
	 * 遍历处理选项。
	 *		L表示仍然没有被解析的块的长度。
	 *		Optptr指针指向已经被解析了的选项块的当前地址。Optptr[1]是选项的长度，optptr[2]是选项指针（选项开始的地方）。
	 * 		Optlen被初始化为当前选项的长度。
	 * 		Is_changed标志用来保存当报头是否已经被修改（这需要重新计算校验和）。
	 */
	for (l = opt->optlen; l > 0; ) {
		switch (*optptr) {
		      case IPOPT_END:
			/**
			 * 在IPOPT_END选项后，不能再有其他选项。因此，一旦找到一个这样的选项，不管其后是什么选项，都被覆盖为IPOPT_END。
			 */
			for (optptr++, l--; l>0; optptr++, l--) {
				if (*optptr != IPOPT_END) {
					*optptr = IPOPT_END;
					opt->is_changed = 1;
				}
			}
			goto eol;
			/**
			 * IPOPT_NOOP用于占位，直接略过。
			 */
		      case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		/**
		 * 以下处理多字节选项。
		 */
		optlen = optptr[1];
		/**
		 * 由于每一个选项的长度包含了最前面的两个字节（type和length），并且它从1开始计数（不是0），如果length小于2或者大于已经被分析的选项块就表示一个错误
		 */
		if (optlen<2 || optlen>l) {
			pp_ptr = optptr;
			goto error;
		}
		switch (*optptr) {
			/**
			 * 严格和宽松的源路由选项。
			 */
		      case IPOPT_SSRR:
		      case IPOPT_LSRR:
			/**
			 * 如果选项长度（包含type和length）小于3，那么该选项将被视为错误选项。
			 * 这是因为该值已经包含了type、length和pointer字段。
			 */
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * 同时，pointer不能比4小，因为第一个3字节的选项已经被type、length、pionter字段使用。
			 */
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/* NB: cf RFC-1812 5.2.4.1 */
			/**
			 * 前现的解析中已经一个源路由选项了。
			 * 由于严格和宽松源路由不能同时并存，因此跳到错误处理。
			 */
			if (opt->srr) {
				pp_ptr = optptr;
				goto error;
			}
			/**
			 * 当输入的skb参数是NULL时，表示ip_options_compile被调用以解析一个出包的选项（由本地生成而不是转发）。
			 */
			if (!skb) {
				if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
					pp_ptr = optptr + 1;
					goto error;
				}
				/**
				 * 在这种情况下，由用户空间提供的地址数组中的第一个IP地址被保存在opt->faddr，然后以memmove运算把数组的其他元素往回移动一个位置，将该地址从数组中删除。
				 * 这个地址随后将被ip_queue_xmit函数取出，这样，那些函数才知道目的IP地址。使用opt->faddr的简单的例子可以在udp_sendmsg中找到。
				 */
				memcpy(&opt->faddr, &optptr[3], 4);
				if (optlen > 7)
					memmove(&optptr[3], &optptr[7], optlen-7);
			}
			/**
			 * opt->is_strictroute被用来告诉调用者：源路由选项是否是一个严格、宽松路由。
			 */
			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
			opt->srr = optptr - iph;
			break;
			/**
			 * 记录路由选项。
			 */
		      case IPOPT_RR:
			/**
			 * 重复选项，错误。
			 */
			if (opt->rr) {
				pp_ptr = optptr;
				goto error;
			}
			/**
			 * 长度非法。
			 */
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * pointer非法。
			 */
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/**
			 * 当前指针小于IP选项总长，IP报头中还有空间记录路由。 
			 */
			if (optptr[2] <= optlen) {
				/**
				 * 空间不足以存储一个地址了。错误。
				 */
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				/**
				 * 处理入包。
				 */
				if (skb) {
					/**
					 * 把首选源IP地址拷贝到报头中的地址列表，然后更新标志is_changed来强迫更新IP校验和。
					 */
					memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
					opt->is_changed = 1;
				}
				/**
				 * 无论如何，该选项的pointer字段都会往前移4个节（IP地址的尺寸）。
				 * 这就说明了为什么ip_forward_options要往回走4个字节，以把IP写入正确的地址。因为ip_forward_options会根据rr_needaddr写入IP地址。
				 */
				optptr[2] += 4;
				/**
				 * 设定rr_needaddr标志，以通知路由子系统，当做出路由决策后，把外出接口的IP地址写入IP报头。
				 */
				opt->rr_needaddr = 1;
			}
			opt->rr = optptr - iph;
			break;
			/**
			 * Timestamp选项
			 */
		      case IPOPT_TIMESTAMP:
			/**
			 * 重复选项。
			 */
			if (opt->ts) {
				pp_ptr = optptr;
				goto error;
			}
			/**
			 * 长度非法。
			 */
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * pointer非法。
			 */
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/**
			 * 还在空间用于保存时间戳。
			 */
			if (optptr[2] <= optlen) {
				__u32 * timeptr = NULL;
				/**
				 * 剩余空间不足以保存时间戳。
				 */
				if (optptr[2]+3 > optptr[1]) {
					pp_ptr = optptr + 2;
					goto error;
				}
				/**
				 * 处理subtype字段
				 */
				switch (optptr[3]&0xF) {
				      case IPOPT_TS_TSONLY:
					opt->ts = optptr - iph;
					/**
					 * 仅当skb不为NULL时（当该选项属于某个入包时），timeptr才会初始化。
					 */
					if (skb) 
						/**
						 * TS_ONLY和TS_TSANDADDR必须记录时间戳.
						 * Timeptr的初始值设置成应该写入到IP报头中的正确地点。
						 */
						timeptr = (__u32*)&optptr[optptr[2]-1];
					/**
					 * ts_needtime为1，对出包来说，ip_options_build会根据这个标志设置时间戳
					 */
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				      case IPOPT_TS_TSANDADDR:
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					/**
					 * 仅当skb不为NULL时（当该选项属于某个入包时），timeptr才会初始化。
					 */
					if (skb) {
						/**
						 * 写入地址。
						 */
						memcpy(&optptr[optptr[2]-1], &rt->rt_spec_dst, 4);
						/**
						 * TS_ONLY和TS_TSANDADDR必须记录时间戳.
						 * Timeptr的初始值设置成应该写入到IP报头中的正确地点。
						 */						
						timeptr = (__u32*)&optptr[optptr[2]+3];
					}
					opt->ts_needaddr = 1;
					/**
					 * ts_needtime为1，对出包来说，ip_options_build会根据这个标志设置时间戳
					 */
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
					  /**
					   * 当子代码为IPOPT_TS_PRESPEC时，只有当下一个要比对的IP地址是系统本地地址时，时间戳才会加进去
					   */
				      case IPOPT_TS_PRESPEC:
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					{
						u32 addr;
						memcpy(&addr, &optptr[optptr[2]-1], 4);
						/** 
						 * 根据路由表，该IP地址可以抵达，而且是单播地址。
						 * 因此，本机不用计算时间戳。
						 */
						if (inet_addr_type(addr) == RTN_UNICAST)
							break;
						/**
						 * 对入包来说，才需要在本函数记录时间戳。
						 */
						if (skb)
							timeptr = (__u32*)&optptr[optptr[2]+3];
					}
					/**
					 * ts_needtime为1，对出包来说，ip_options_build会根据这个标志设置时间戳
					 */					
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				      default:
					if (!skb && !capable(CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				/**
				 * 取决于正在处理的子选项，时间戳必须写入IP报头中的不同偏移量处。前面是根据情况对timeptr初始化。
				 * 现在是把时间戳拷贝到正确位置。根据子选项而定，ts_needtime和tr_needaddr也会被初始化。
				 */
				if (timeptr) {
					struct timeval tv;
					__u32  midtime;
					do_gettimeofday(&tv);
					midtime = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
					memcpy(timeptr, &midtime, sizeof(__u32));
					/**
					 * 对入包来说，timeptr不为NULL，这里设置修改标志，这样，就会重新计算校验和了。
					 * 因为这种情况下，报头已经发生了变化。
					 */
					opt->is_changed = 1;
				}
			} else {/* 这一部分是处理时间戳空间不足的溢出 */
				unsigned overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				opt->ts = optptr - iph;
				if (skb) {
					optptr[3] = (optptr[3]&0xF)|((overflow+1)<<4);
					opt->is_changed = 1;
				}
			}
			break;
		      case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			/**
			 * Router Alert选项的最后两个字节必须为0.
			 */
			if (optptr[2] == 0 && optptr[3] == 0)
				/**
				 * 设置router_alert供ip_forward处理。
				 */
				opt->router_alert = optptr - iph;
			break;
		      case IPOPT_SEC:
		      case IPOPT_SID:
		      default:
			if (!skb && !capable(CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

/**
 * 运行到此，说明报头中有错误发生。
 */
error:
	/**
	 * 如果是入包，则向对方发送ICMP消息。
	 */
	if (skb) {
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((pp_ptr-iph)<<24));
	}
	return -EINVAL;
}


/*
 *	Undo all the changes done by ip_options_compile().
 */

void ip_options_undo(struct ip_options * opt)
{
	if (opt->srr) {
		unsigned  char * optptr = opt->__data+opt->srr-sizeof(struct  iphdr);
		memmove(optptr+7, optptr+3, optptr[1]-7);
		memcpy(optptr+3, &opt->faddr, 4);
	}
	if (opt->rr_needaddr) {
		unsigned  char * optptr = opt->__data+opt->rr-sizeof(struct  iphdr);
		optptr[2] -= 4;
		memset(&optptr[optptr[2]-1], 0, 4);
	}
	if (opt->ts) {
		unsigned  char * optptr = opt->__data+opt->ts-sizeof(struct  iphdr);
		if (opt->ts_needtime) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
			if ((optptr[3]&0xF) == IPOPT_TS_PRESPEC)
				optptr[2] -= 4;
		}
		if (opt->ts_needaddr) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
		}
	}
}

/**
 * 此函数会接收一群选项，用ip_options_compile解析，然后把结果存储在其分配的一个ip_optioins结构。此函数也可从内核空间或用户空间接收输入选项
 */
int ip_options_get(struct ip_options **optp, unsigned char *data, int optlen, int user)
{
	struct ip_options *opt;

	opt = kmalloc(sizeof(struct ip_options)+((optlen+3)&~3), GFP_KERNEL);
	if (!opt)
		return -ENOMEM;
	memset(opt, 0, sizeof(struct ip_options));
	if (optlen) {
		if (user) {
			if (copy_from_user(opt->__data, data, optlen)) {
				kfree(opt);
				return -EFAULT;
			}
		} else
			memcpy(opt->__data, data, optlen);
	}
	while (optlen & 3)
		opt->__data[optlen++] = IPOPT_END;
	opt->optlen = optlen;
	opt->is_data = 1;
	opt->is_setbyuser = 1;
	if (optlen && ip_options_compile(opt, NULL)) {
		kfree(opt);
		return -EINVAL;
	}
	if (*optp)
		kfree(*optp);
	*optp = opt;
	return 0;
}

/**
 * 转发一个包时，有些选项可能必须被处理。
 * Ip_options_compile会解析一些选项，然后对用于存储解析结果的ip_options结构的一组标志做初始化。
 */
void ip_forward_options(struct sk_buff *skb)
{
	struct   ip_options * opt	= &(IPCB(skb)->opt);
	unsigned char * optptr;
	struct rtable *rt = (struct rtable*)skb->dst;
	unsigned char *raw = skb->nh.raw;

	if (opt->rr_needaddr) {
		optptr = (unsigned char *)raw + opt->rr;
		ip_rt_get_source(&optptr[optptr[2]-5], rt);
		opt->is_changed = 1;
	}
	if (opt->srr_is_hit) {
		int srrptr, srrspace;

		optptr = raw + opt->srr;

		for ( srrptr=optptr[2], srrspace = optptr[1];
		     srrptr <= srrspace;
		     srrptr += 4
		     ) {
			if (srrptr + 3 > srrspace)
				break;
			if (memcmp(&rt->rt_dst, &optptr[srrptr-1], 4) == 0)
				break;
		}
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_rt_get_source(&optptr[srrptr-1], rt);
			skb->nh.iph->daddr = rt->rt_dst;
			optptr[2] = srrptr+4;
		} else if (net_ratelimit())
			printk(KERN_CRIT "ip_forward(): Argh! Destination lost!\n");
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			ip_rt_get_source(&optptr[optptr[2]-9], rt);
			opt->is_changed = 1;
		}
	}
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(skb->nh.iph);
	}
}

/**
 * 处理基于源站寻路。
 * 从IP头部提取出要使用的下一跳，并调用ip_route_input来进行第二次路由查找。
 * 第二次路由查找使用更新的查找结果覆盖原来的skb->dst。
 */
int ip_options_rcv_srr(struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	int srrspace, srrptr;
	u32 nexthop;
	struct iphdr *iph = skb->nh.iph;
	unsigned char * optptr = skb->nh.raw + opt->srr;
	struct rtable *rt = (struct rtable*)skb->dst;
	struct rtable *rt2;
	int err;

	if (!opt->srr)
		return 0;

	if (skb->pkt_type != PACKET_HOST)
		return -EINVAL;
	if (rt->rt_type == RTN_UNICAST) {
		if (!opt->is_strictroute)
			return 0;
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(16<<24));
		return -EINVAL;
	}
	if (rt->rt_type != RTN_LOCAL)
		return -EINVAL;

	for (srrptr=optptr[2], srrspace = optptr[1]; srrptr <= srrspace; srrptr += 4) {
		if (srrptr + 3 > srrspace) {
			icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((opt->srr+2)<<24));
			return -EINVAL;
		}
		memcpy(&nexthop, &optptr[srrptr-1], 4);

		rt = (struct rtable*)skb->dst;
		skb->dst = NULL;
		err = ip_route_input(skb, nexthop, iph->saddr, iph->tos, skb->dev);
		rt2 = (struct rtable*)skb->dst;
		if (err || (rt2->rt_type != RTN_UNICAST && rt2->rt_type != RTN_LOCAL)) {
			ip_rt_put(rt2);
			skb->dst = &rt->u.dst;
			return -EINVAL;
		}
		ip_rt_put(rt);
		if (rt2->rt_type != RTN_LOCAL)
			break;
		/* Superfast 8) loopback forward */
		memcpy(&iph->daddr, &optptr[srrptr-1], 4);
		opt->is_changed = 1;
	}
	if (srrptr <= srrspace) {
		opt->srr_is_hit = 1;
		opt->is_changed = 1;
	}
	return 0;
}

EXPORT_SYMBOL(ip_options_compile);
EXPORT_SYMBOL(ip_options_undo);
