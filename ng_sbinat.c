/*-
 * Copyright 2005, Gleb Smirnoff <glebius@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/netgraph/ng_sbinat.c,v 1.10.2.2.2.1 2008/11/25 02:59:29 kensmith Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/ctype.h>
#include <sys/errno.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_var.h>
#include <net/if_vlan_var.h>
#include <net/bpf.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <machine/in_cksum.h>

#include <netinet/libalias/alias.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include "ng_sbinat.h"
#include <netgraph/netgraph.h>

static ng_constructor_t	ng_sbinat_constructor;
static ng_rcvmsg_t	ng_sbinat_rcvmsg;
static ng_shutdown_t	ng_sbinat_shutdown;
static ng_newhook_t	ng_sbinat_newhook;
static ng_rcvdata_t	ng_sbinat_rcvdata;
static ng_disconnect_t	ng_sbinat_disconnect;

//static unsigned int	ng_sbinat_translate_flags(unsigned int x);


/* List of commands and how to convert arguments to/from ASCII. */
static const struct ng_cmdlist ng_sbinat_cmdlist[] = {
	{
	  NGM_SBINAT_COOKIE,
	  NGM_SBINAT_SET_IN_ADDR,
	  "setinaddr",
	  &ng_parse_ipaddr_type,
	  NULL
	},
	{
	  NGM_SBINAT_COOKIE,
	  NGM_SBINAT_SET_OUT_ADDR,
	  "setoutaddr",
	  &ng_parse_ipaddr_type,
	  NULL
	},
	{ 0 }
};

/* Netgraph node type descriptor. */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_SBINAT_NODE_TYPE,
	.constructor =	ng_sbinat_constructor,
	.rcvmsg =	ng_sbinat_rcvmsg,
	.shutdown =	ng_sbinat_shutdown,
	.newhook =	ng_sbinat_newhook,
	.rcvdata =	ng_sbinat_rcvdata,
	.disconnect =	ng_sbinat_disconnect,
	.cmdlist =	ng_sbinat_cmdlist,
};
NETGRAPH_INIT(sbinat, &typestruct);
//MODULE_DEPEND(ng_sbinat, libalias, 1, 1, 1);


/* Information we store for each node. */
struct ng_sbinat_priv {
	node_p		node;		/* back pointer to node */
	hook_p		in;		/* hook for demasquerading */
	hook_p		out;		/* hook for masquerading */
	u_int32_t 	flags;
	struct in_addr	in_addr;
	struct in_addr	out_addr;
};
typedef struct ng_sbinat_priv *priv_p;

/* Values of flags */
#define	NGSBINAT_CONNECTED		0x1	/* We have both hooks connected */
#define	NGSBINAT_ADDR_DEFINED	0x2	/* NGM_SBINAT_SET_IPADDR happened */

static int
ng_sbinat_constructor(node_p node)
{
	priv_p priv;

	/* Initialize private descriptor. */
	MALLOC(priv, priv_p, sizeof(*priv), M_NETGRAPH,
		M_NOWAIT | M_ZERO);
	if (priv == NULL)
		return (ENOMEM);

	/* Link structs together. */
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;

	/*
	 * libalias is not thread safe, so our node
	 * must be single threaded.
	 */
	//NG_NODE_FORCE_WRITER(node);

	return (0);
}

static int
ng_sbinat_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	if (strcmp(name, NG_SBINAT_HOOK_IN) == 0) {
		priv->in = hook;
	} else if (strcmp(name, NG_SBINAT_HOOK_OUT) == 0) {
		priv->out = hook;
	} else
		return (EINVAL);

	if (priv->out != NULL &&
	    priv->in != NULL)
		priv->flags |= NGSBINAT_CONNECTED;

	return(0);
}

static int
ng_sbinat_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	struct ng_mesg *msg;
	int error = 0;

	NGI_GET_MSG(item, msg);

	switch (msg->header.typecookie) {
	case NGM_SBINAT_COOKIE:
		switch (msg->header.cmd) {
		case NGM_SBINAT_SET_IN_ADDR:
		    {
			struct in_addr *const ia = (struct in_addr *)msg->data;

			if (msg->header.arglen < sizeof(*ia)) {
				error = EINVAL;
				break;
			}

			priv->in_addr = *ia;
		    }
			break;
		case NGM_SBINAT_SET_OUT_ADDR:
		    {
			struct in_addr *const ia = (struct in_addr *)msg->data;

			if (msg->header.arglen < sizeof(*ia)) {
				error = EINVAL;
				break;
			}

			priv->out_addr = *ia;
		    }
			break;
		default:
			error = EINVAL;		/* unknown command */
			break;
		}
		break;
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);
	return (error);
}

#define TCPMSS_ADJUST_CHECKSUM(acc0, cksum) do {        \
	int acc = acc0 + cksum;                         \
        if (acc < 0) {                                  \
                acc = -acc;                             \
                acc = (acc >> 16) + (acc & 0xffff);     \
                acc += acc >> 16;                       \
                cksum = (u_short) ~acc;                 \
        } else {                                        \
                acc = (acc >> 16) + (acc & 0xffff);     \
                acc += acc >> 16;                       \
                cksum = (u_short) acc;                  \
        }                                               \
} while (0);


void recalc_cksum(struct ip *ip, struct mbuf *m, int accumulate){
	TCPMSS_ADJUST_CHECKSUM(accumulate, ip->ip_sum);
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		if( (m->m_pkthdr.csum_flags & CSUM_TCP) == 0 ){
			struct tcphdr *th = (struct tcphdr *)((caddr_t)ip + (ip->ip_hl << 2));
			TCPMSS_ADJUST_CHECKSUM(accumulate, th->th_sum);
		}
		break;
	case IPPROTO_UDP:
		if( (m->m_pkthdr.csum_flags & CSUM_UDP) == 0 ){
			struct udphdr *uh = (struct udphdr *)((caddr_t)ip + (ip->ip_hl << 2));
			TCPMSS_ADJUST_CHECKSUM(accumulate, uh->uh_sum);
		}
		break;
	}
}

static int
ng_sbinat_rcvdata(hook_p hook, item_p item )
{
	const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct mbuf	*m;
	struct ip	*ip;
	int error = 0;
	char *c;
	int pullup_len = 0;
	int accumulate;

	/* We have no required hooks. */
	if (!(priv->flags & NGSBINAT_CONNECTED)) {
		NG_FREE_ITEM(item);
		log(LOG_INFO,"sbinat: recvd pkt w/o all connected hooks. dropping.\n");
		return (ENXIO);
	}

	/* We have no alias address yet to do anything. */
	//if (!(priv->flags & NGSBINAT_ADDR_DEFINED))
	//	goto send;

	m = NGI_M(item);

	if ((m = m_megapullup(m, m->m_pkthdr.len)) == NULL) {
		NGI_M(item) = NULL;	/* avoid double free */
		NG_FREE_ITEM(item);
		log(LOG_INFO,"sbinat: returning ENOBUFS at line %d\n", __LINE__);
		return (ENOBUFS);
	}

	NGI_M(item) = m;

	struct ether_header *eh;
	//uint16_t etype;

#define M_CHECK(length) do {                                    \
        pullup_len += length;                                   \
        if ((m)->m_pkthdr.len < (pullup_len)) {                 \
                NG_FREE_ITEM(item);                             \
		log(LOG_INFO,"sbinat: returning EINVAL at line %d\n", __LINE__); \
                return (EINVAL);                                \
        }                                                       \
        if ((m)->m_len < (pullup_len) &&                        \
           (((m) = m_pullup((m),(pullup_len))) == NULL)) {      \
                NG_FREE_ITEM(item);                             \
		log(LOG_INFO,"sbinat: returning ENOBUFS at line %d\n", __LINE__); \
                return (ENOBUFS);                               \
        }                                                       \
} while (0)

	M_CHECK(sizeof(struct ether_header));
	eh = mtod(m, struct ether_header *);

	/* Make sure this is IP frame. */
	switch( ntohs(eh->ether_type) ){
		case ETHERTYPE_IP:
			M_CHECK(sizeof(struct ip));
			ip = (struct ip *)(eh + 1);
			c = (char *)(eh + 1);
			break;

		default:
			// all other protos, pass them unchanged
			goto send;
			break;
	}

        if ((ip->ip_off & htons(IP_OFFMASK)) == 0) {
                /*
                 * In case of IP header with options, we haven't pulled
                 * up enough, yet.
                 */
                pullup_len += (ip->ip_hl << 2) - sizeof(struct ip);

                switch (ip->ip_p) {
                case IPPROTO_TCP:
                        M_CHECK(sizeof(struct tcphdr));
                        break;
                case IPPROTO_UDP:
                        M_CHECK(sizeof(struct udphdr));
                        break;
                }
        }

	if (hook == priv->in) {
		if(*(u_int16_t*)(&ip->ip_src) == *(u_int16_t*)(&priv->in_addr)){
			accumulate  = *(u_int16_t*)(&ip->ip_src);
			*(u_int16_t*)(&ip->ip_src) = *(u_int16_t*)(&priv->out_addr);
			accumulate -= *(u_int16_t*)(&ip->ip_src);
			recalc_cksum(ip,m,accumulate);
		}
	} else if (hook == priv->out) {
		if(*(u_int16_t*)(&ip->ip_dst) == *(u_int16_t*)(&priv->out_addr)){
			accumulate  = *(u_int16_t*)(&ip->ip_dst);
			*(u_int16_t*)(&ip->ip_dst) = *(u_int16_t*)(&priv->in_addr);
			accumulate -= *(u_int16_t*)(&ip->ip_dst);
			recalc_cksum(ip,m,accumulate);
		}
	} else {
		log(LOG_ERR,"sbinat: unknown hook at line %d\n", __LINE__);
		panic("ng_sbinat: unknown hook!\n");
	}

	m->m_pkthdr.len = m->m_len = ntohs(ip->ip_len) + sizeof(struct ether_header);


send:
	if (hook == priv->in)
		NG_FWD_ITEM_HOOK(error, item, priv->out);
	else
		NG_FWD_ITEM_HOOK(error, item, priv->in);

	return (error);
}

static int
ng_sbinat_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);

	FREE(priv, M_NETGRAPH);

	return (0);
}

static int
ng_sbinat_disconnect(hook_p hook)
{
	const priv_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));

	priv->flags &= ~NGSBINAT_CONNECTED;

	if (hook == priv->out)
		priv->out = NULL;
	if (hook == priv->in)
		priv->in = NULL;

	if (priv->out == NULL && priv->in == NULL)
		ng_rmnode_self(NG_HOOK_NODE(hook));

	return (0);
}

/*
static unsigned int
ng_sbinat_translate_flags(unsigned int x)
{
	unsigned int	res = 0;
	
	if (x & NG_SBINAT_LOG)
		res |= PKT_ALIAS_LOG;
	if (x & NG_SBINAT_DENY_INCOMING)
		res |= PKT_ALIAS_DENY_INCOMING;
	if (x & NG_SBINAT_SAME_PORTS)
		res |= PKT_ALIAS_SAME_PORTS;
	if (x & NG_SBINAT_UNREGISTERED_ONLY)
		res |= PKT_ALIAS_UNREGISTERED_ONLY;
	if (x & NG_SBINAT_RESET_ON_ADDR_CHANGE)
		res |= PKT_ALIAS_RESET_ON_ADDR_CHANGE;
	if (x & NG_SBINAT_PROXY_ONLY)
		res |= PKT_ALIAS_PROXY_ONLY;
	if (x & NG_SBINAT_REVERSE)
		res |= PKT_ALIAS_REVERSE;

	return (res);
}
*/
