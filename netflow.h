/*
 * Copyright (c) 2004-2019  by Motonori Shindo <motonori@shin.do>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */


#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>

#define EXPR_TYPE_SEQ	1	/* Sequential */
#define EXPR_TYPE_RND	2	/* Random */
#define EXPR_TYPE_PRB	3	/* Probabilistic */

typedef struct val_expr {
  int mode;		/* EXPR_TYPE_SEQ, EXPR_TYPE_RND or EXPR_TYPE_PRB */
  long start;		/* inclusive */
  long end;		/* inclusive */
  long step;
  long vals[100];
  long cur;
} val_expr_t;

typedef struct ipaddr_expr {
  val_expr_t exp[4];
} ipaddr_expr_t;

#define TRUE	1
#define FALSE	0

#define ETH_MTU		1500

#define NF_VERSION_V1	1
#define NF_VERSION_V5	5
#define NF_VERSION_V7	7
#define NF_VERSION_V8	8
#define NF_VERSION_V9	9

/* (1500 - 20 - 8 - 24) / 48 = 30 flow records */
#define NF5_MAX_FLOWREC 30

#define MAX_FLOW_INFO	NF5_MAX_FLOWREC

struct nf_v5_hdr {	/*  24 octets */
  u_int16_t version;		/* 5 */
  u_int16_t count;
  u_int32_t sysup_time;
  u_int32_t unix_secs;
  u_int32_t unix_nsecs;
  u_int32_t flow_sequence;   /* # of total flows seen (this differs in V9) */
  u_int8_t engine_type;	     /* 0: RP, 1: VIP/LC */
  u_int8_t engine_id;
  u_int16_t sampling;
};

struct nf_v5_rec {	/* 48 octets */
  struct in_addr src_addr;
  struct in_addr dst_addr;
  struct in_addr nexthop;
  u_int16_t in_if;
  u_int16_t out_if;
  u_int32_t packets;
  u_int32_t octets;
  u_int32_t first;
  u_int32_t last;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t pad1;
  u_int8_t tcp_flags;
  u_int8_t ip_proto;
  u_int8_t tos;
  u_int16_t src_as;
  u_int16_t dst_as;
  u_int8_t src_mask;
  u_int8_t dst_mask;
  u_int16_t pad2;
};

struct nf_v5_pdu {
  struct nf_v5_hdr hdr;
  struct nf_v5_rec rec[NF5_MAX_FLOWREC];
};

struct flow_info {
  struct in_addr src_addr;
  struct in_addr dst_addr;
  struct in_addr nexthop;
  u_int16_t in_if;
  u_int16_t out_if;
  u_int32_t packets;
  u_int32_t octets;
  u_int32_t first;
  u_int32_t last;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t pad1;
  u_int8_t tcp_flags;
  u_int8_t ip_proto;
  u_int8_t tos;
  u_int16_t src_as;
  u_int16_t dst_as;
  u_int8_t src_mask;
  u_int8_t dst_mask;
};


struct flow_exporter {
  struct in_addr collector;	/* address of collector */
  u_int16_t port;
  int sock;
  struct sockaddr_in to;
  struct timeval start;		/* start time of this exporter */
  val_expr_t engine_type;
  val_expr_t engine_id;
  long flow_seen;	/* accumulative number of flow record seen */
  long pdu_sent;	/* accumulative number of flow PDU sent */
  int flow_cnt;		/* # of flow_info occupied */
  int bucket_size;	/* when flow_cnt reaches bucket_size, flow_info will be flushed */
  struct flow_info fi[MAX_FLOW_INFO];
};
