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

/* TODO:
  - dns lookup for collector
  - source ip spoof
  - step support in range expression
  - absolute value for firstseen and last seen
*/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <signal.h>

#include "netflow.h"

/* option value has to be smaller than '0' (48) */
#define OPT_VERSION	1
#define OPT_ENGINETYPE	2
#define OPT_ENGINEID	3
#define OPT_SRCADDR	4
#define OPT_DSTADDR	5
#define OPT_NEXTHOP	6
#define OPT_INPUTIF	7
#define OPT_OUTPUTIF	8
#define OPT_PACKETS	9
#define OPT_OCTETS	10
#define OPT_FIRSTSEEN	11
#define OPT_LASTSEEN	12
#define OPT_SRCPORT	13
#define OPT_DSTPORT	14
#define OPT_TCPFLAGS	15
#define OPT_PROTOCOL	16
#define OPT_TOS		17
#define OPT_SRCAS	18
#define OPT_DSTAS	19
#define OPT_SRCMASK	20
#define OPT_DSTMASK	21

struct flow_exporter Ex;

int debug = 0;
int nosend_f = FALSE;

void usage(void)
{
  fprintf(stderr,
"Usage: flowgen [options] [flowrec-options] <collector>\n\
 options:\n\
   -n, --count <num>\n\
   -p, --port <num>\n\
   -V, --version <version>\n\
   -f, --flowrec <# of flow records in packet>\n\
   -d, --debug <debug level>\n\
   -N, --nosend\n\
   -h, --help\n\
 flowrec-options:\n\
   -w, --wait <wait time>\n\
   -i, --interval <interval>\n\
   --enginetype <engine type>\n\
   --engineid <engine id>\n\
   --srcaddr <src ip address>\n\
   --dstaddr <dst ip address>\n\
   --nexthop <nexthop ip address>\n\
   --inputif <input IfIndex>\n\
   --outputif <output IfIndex>\n\
   --packets <# of packets>\n\
   --octets <# of octets>\n\
   --firstseen <first seen>\n\
   --lastseen <last seen>\n\
   --srcport <src port>\n\
   --dstport <dst port>\n\
   --tcpflags <tcp flags>\n\
   --protocol <protocol number>\n\
   --tos <tos value>\n\
   --srcas <src AS#>\n\
   --dstas <dst AS#>\n\
   --srcmask <src subnet mask length>\n\
   --dstmask <dst subnet mask length>\n\n\
  Numbers can be expressed using the following meta characters:\n\
    111      (static)\n\
    111-222  (sequential)\n\
    111:222  (random)\n\
    100@70,200@20,300@10   (probabilistic)\n");
  exit(1);
}

void fatal(const char *msg)
{
  printf("%s\n", msg);
  exit(1);
}


void compile_expr(const char *str, val_expr_t *e)
{

  /* supports following formats:

  [Examples]
  111      (static)
  111-222  (sequential)
  111:222  (random)
  100@70,200@20,300@10   (probabilistic)

  */

  if (!strchr(str, '-') && !strchr(str, ':') && !strchr(str, '@')) {
    e->mode = EXPR_TYPE_SEQ;
    e->start = e->end = atol(str);
    e->step = 0;
    e->cur = e->start;
    return;
  }

  if (strchr(str, '-')) {
    e->mode = EXPR_TYPE_SEQ;
    sscanf(str, "%ld-%ld", &e->start, &e->end);
    e->step = 1;
    e->cur = e->start;
    return;
  }

  if (strchr(str, ':')) {
    e->mode = EXPR_TYPE_RND;
    sscanf(str, "%ld:%ld", &e->start, &e->end);
    e->step = 1;
    e->cur = e->start;
    return;
  }

  if (strchr(str, '@')) {
    const char *s = str;
    const char *c;
    long val;
    int  p, psum = 0;

    e->mode = EXPR_TYPE_PRB;
    while (*s) {
      int i;
      sscanf(s, "%ld@%d", &val, &p);
      if (p + psum > 100)
	break;
      for (i=0; i< p; i++) {
	e->vals[psum + i] = val;
      }
      psum += p;
      c = strchr(s, ',');	/* XXX: consider case where s ends with ','! */
      if (c)
	s = c + 1;
      else
	break;
    }
    e->start = e->end = e->step = e->cur = 0; /* XXX */
    return;
  }

  fatal("invalid expression");

}


void compile_ipaddr_expr(const char *str, ipaddr_expr_t *ie)
{
  char buf[256];	/* XXX */
  val_expr_t octet;
  const char *p = str;
  int i;

  /* str = "<val_expr>.<val_expr>.<val_expr>.<val_expr>" */

  for (i=0; i<4; i++) {
    memset(buf, 0, sizeof(buf));
    while (1) {
      if (*p == '.' || *p == '\0') {
	if (p - str >= sizeof(buf) - 1)
	  fatal("out of range");
	strncpy(buf, str, p - str);
	compile_expr(buf, &octet);
	memcpy(&(ie->exp[i]), &octet, sizeof(val_expr_t));
	if (*p)
	  str = ++p;
	break;
      } else {
	p++;
	continue;
      }
    }
  }
}


long expr_val(val_expr_t *e)
{
  long val = e->cur;

  switch (e->mode) {
  case EXPR_TYPE_SEQ:
    e->cur += e->step;
    if (e->cur > e->end)
      e->cur = e->start;
    return val;
  case EXPR_TYPE_RND:
    e->cur =
      (long)(random()/(double)RAND_MAX * (e->end - e->start) + e->start);
    if (e->cur < e->start || e->cur > e->end)
      fatal("unexpected random number");
    return e->cur;
  case EXPR_TYPE_PRB:
    e->cur = e->vals[(int)(random()/(double)RAND_MAX * (100-1))];
    return e->cur;
  default:
    fatal("unknown expr mode");
  }
  return 0L;	/* should not reach here */
}


void expr_addr(char *ipaddr, ipaddr_expr_t *ie)
{
  int octet[4];
  int i;

  for (i=0; i<4; i++) {
    octet[i] = expr_val(&(ie->exp[i]));
    if (octet[i] < 0 || octet[i] > 255) {
      fatal("ipaddr_expr error");
    }
  }
  sprintf(ipaddr, "%d.%d.%d.%d", octet[0], octet[1], octet[2], octet[3]);

}

/*
 * Returns sysuptime in millisecond
 *
 */
#if 0
/*
 * XXX: this version is highly inefficient!
 */
u_int32_t sysuptime(void)
{
  double uptime, dummy;
  FILE *fp;

  fp = fopen("/proc/uptime", "r");
  fscanf(fp, "%lf %lf", &uptime, &dummy);
  fclose(fp);

  return ((u_int32_t)(uptime * 1000.0));
}
#endif

/*
 * Returns sysuptime (in millisecond)
 *
 */
#if defined (__linux__)
u_int32_t sysuptime(void)
{
  static int initialized = 0;
  static double uptime;
  double dummy;
  static struct timeval init_tv;
  struct timeval tv;

  FILE *fp;

  if (!initialized) {
    fp = fopen("/proc/uptime", "r");
    fscanf(fp, "%lf %lf", &uptime, &dummy);
    fclose(fp);
    uptime *= 1000.0;	/* in milisec */
    gettimeofday(&init_tv, (struct timezone *)0);
    initialized = 1;
    return ((u_int32_t)uptime);
  } else {
    gettimeofday(&tv, (struct timezone *)0);
    return ((u_int32_t)(uptime +
			tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0 -
			init_tv.tv_sec * 1000.0 + init_tv.tv_usec / 1000.0));
  }
}
#endif

#if defined (__FreeBSD__) || defined (__APPLE__)
#include <sys/sysctl.h>
u_int32_t sysuptime(void)
{
  time_t now, uptime = 0;
  struct timeval boottime;
  int mib[2];
  size_t size;

  mib[0] = CTL_KERN;
  mib[1] = KERN_BOOTTIME;
  size = sizeof(boottime);
  if (sysctl(mib, 2, &boottime, &size, NULL, 0) != -1) {
    time(&now);
    uptime = now - boottime.tv_sec;
  }
  return uptime * 1000;		/* returns in millisec */
}
#endif

void flush_flow(void)
{
  struct timeval tv;
  struct nf_v5_pdu pdu;
  int i;

  gettimeofday(&tv, (struct timezone *)0);

  pdu.hdr.version = htons(NF_VERSION_V5);
  pdu.hdr.count = htons(Ex.flow_cnt);
  pdu.hdr.sysup_time = htonl(sysuptime());
  pdu.hdr.unix_secs = htonl(tv.tv_sec);
  pdu.hdr.unix_nsecs = htonl(tv.tv_usec * 1000);
  pdu.hdr.flow_sequence = htonl(Ex.flow_seen);
  pdu.hdr.engine_type = expr_val(&Ex.engine_type) & 0xff;
  pdu.hdr.engine_id = expr_val(&Ex.engine_id) & 0xff;
  pdu.hdr.sampling = htons(0);

  memset(&pdu.rec[0], 0, sizeof(struct nf_v5_rec) * NF5_MAX_FLOWREC);

  for (i=0; i < Ex.flow_cnt; i++) {
    memcpy(&pdu.rec[i].src_addr, &Ex.fi[i].src_addr, sizeof(struct in_addr));
    memcpy(&pdu.rec[i].dst_addr, &Ex.fi[i].dst_addr, sizeof(struct in_addr));
    memcpy(&pdu.rec[i].nexthop, &Ex.fi[i].nexthop, sizeof(struct in_addr));
    pdu.rec[i].in_if = htons(Ex.fi[i].in_if);
    pdu.rec[i].out_if = htons(Ex.fi[i].out_if);
    pdu.rec[i].packets = htonl(Ex.fi[i].packets);
    pdu.rec[i].octets = htonl(Ex.fi[i].octets);
    pdu.rec[i].first = htonl(Ex.fi[i].first);
    pdu.rec[i].last = htonl(Ex.fi[i].last);
    pdu.rec[i].src_port = htons(Ex.fi[i].src_port);
    pdu.rec[i].dst_port = htons(Ex.fi[i].dst_port);
    pdu.rec[i].tcp_flags = Ex.fi[i].tcp_flags;
    pdu.rec[i].ip_proto = Ex.fi[i].ip_proto;
    pdu.rec[i].tos = Ex.fi[i].tos;
    pdu.rec[i].src_as = htons(Ex.fi[i].src_as);
    pdu.rec[i].dst_as = htons(Ex.fi[i].dst_as);
    pdu.rec[i].src_mask = Ex.fi[i].src_mask;
    pdu.rec[i].dst_mask = Ex.fi[i].dst_mask;
  }

  if (!nosend_f)
    if (sendto(Ex.sock, &pdu,
	       sizeof(struct nf_v5_hdr) +
	       sizeof(struct nf_v5_rec) * Ex.flow_cnt, 0,
	       (struct sockaddr *)&Ex.to, sizeof(Ex.to)) == -1)
      perror("sendto");


  Ex.pdu_sent++;
  Ex.flow_cnt = 0;
}

void add_flow(struct flow_info *fi)
{
  if (Ex.flow_cnt < Ex.bucket_size) {
    memcpy(&Ex.fi[Ex.flow_cnt++], fi, sizeof(struct flow_info));
    Ex.flow_seen++;
  }
  if (Ex.flow_cnt == Ex.bucket_size) {
    flush_flow();
  }
}

void cleanup(int val)
{
  struct timeval now;

  flush_flow();
  fprintf(stderr, "\n%lu flows seen, %lu PDUs sent ",
	  Ex.flow_seen, Ex.pdu_sent);

  /* XXX: only care about sec, not usec */
  gettimeofday(&now, (struct timezone *)0);
  fprintf(stderr, "(session rate = %lu/sec)\n",
	  Ex.flow_seen / (now.tv_sec - Ex.start.tv_sec));

  exit(0);
}


void init_exporter(const char *dst, u_int16_t port, u_int32_t flowrec_count)
{
  struct sigaction sigact;

  gettimeofday(&Ex.start, (struct timezone *)0);

  /* XXX: assumes dst is in XXX.XXX.XXX.XXX format */
  inet_aton(dst, &Ex.collector);

  Ex.port = port;

  if ((Ex.sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  memset(&Ex.to, 0, sizeof(Ex.to));
  Ex.to.sin_family = AF_INET;
  Ex.to.sin_port = htons(port);
  memcpy(&Ex.to.sin_addr, &Ex.collector, sizeof(Ex.collector));

  Ex.flow_seen = 0L;
  Ex.pdu_sent = 0L;
  Ex.flow_cnt = 0;
  Ex.bucket_size = flowrec_count;

  memset(Ex.fi, 0, sizeof(struct flow_info) * MAX_FLOW_INFO);

  srandom((unsigned int)time(NULL));	/* XXX */

  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_handler = cleanup;

  sigaction(SIGINT, &sigact, NULL);

}


/*
 *
 *
 */
int main(int argc, char **argv)
{
  unsigned long count = 0L;
  char *spoofed_addr = NULL;
  u_int16_t port = 2055;
  char *wait = "0";
  char *interval = "1";
  u_int32_t flowrec_count = NF5_MAX_FLOWREC;
  char *engine_type = "1";
  char *engine_id = "1";
  char *src_addr = "10.0.0.1:254";
  char *dst_addr = "20.0.0.1:254";
  char *nexthop = "30.0.0.254";
  char *in_if = "1";
  char *out_if = "2";
  char *packets = "10:1000";
  char *octets = "300:300000";
  char *first = "10:1000";
  char *last = "0";	/* 0 = now */
  u_int32_t ut;
  char *src_port = "1001-2000";
  char *dst_port = "3001-4000";
  char *tcp_flags = "27";
  char *proto = "6";
  char *tos = "0";
  char *src_as = "101-110";
  char *dst_as = "201-210";
  char *src_mask = "24";
  char *dst_mask = "24";
  val_expr_t
    wait_exp, intvl_exp, iif_exp, oif_exp, pkt_exp, oct_exp,
    fseen_exp, lseen_exp, srcp_exp, dstp_exp, tcpf_exp,
    proto_exp, tos_exp, srcas_exp, dstas_exp, srcmask_exp, dstmask_exp;
  ipaddr_expr_t
    srcaddr_exp, dstaddr_exp, nhop_exp;
  struct flow_info fi;
  long n = 0;
  int wait_f = FALSE;
  int c;

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      /*
	const char *name
	int has_arg
	int *flag
	int val
      */
      {"count",		required_argument, NULL, 'n'},
      {"spoof",		required_argument, NULL, 's'},
      {"port",		required_argument, NULL, 'p'},
      {"wait",		required_argument, NULL, 'w'},
      {"interval", 	required_argument, NULL, 'i'},
      {"flowrec",       required_argument, NULL, 'f'},
      {"debug",    	required_argument, NULL, 'd'},
      {"nosend",   	no_argument,       NULL, 'N'},
      {"help",     	no_argument,       NULL, 'h'},
      {"enginetype", 	required_argument, NULL, OPT_ENGINETYPE},
      {"engineid", 	required_argument, NULL, OPT_ENGINEID},
      {"srcaddr",  	required_argument, NULL, OPT_SRCADDR},
      {"dstaddr",  	required_argument, NULL, OPT_DSTADDR},
      {"nexthop",  	required_argument, NULL, OPT_NEXTHOP},
      {"inputif",  	required_argument, NULL, OPT_INPUTIF},
      {"outputif", 	required_argument, NULL, OPT_OUTPUTIF},
      {"packets",  	required_argument, NULL, OPT_PACKETS},
      {"octets",   	required_argument, NULL, OPT_OCTETS},
      {"firstseen",	required_argument, NULL, OPT_FIRSTSEEN},
      {"lastseen", 	required_argument, NULL, OPT_LASTSEEN},
      {"srcport",  	required_argument, NULL, OPT_SRCPORT},
      {"dstport",  	required_argument, NULL, OPT_DSTPORT},
      {"tcpflags", 	required_argument, NULL, OPT_TCPFLAGS},
      {"protocol", 	required_argument, NULL, OPT_PROTOCOL},
      {"tos", 		required_argument, NULL, OPT_TOS},
      {"srcas",    	required_argument, NULL, OPT_SRCAS},
      {"dstas",    	required_argument, NULL, OPT_DSTAS},
      {"srcmask",  	required_argument, NULL, OPT_SRCMASK},
      {"dstmask",  	required_argument, NULL, OPT_DSTMASK},
      {NULL, 0, NULL, 0}
    };

    c = getopt_long(argc, argv, "n:s:p:w:i:f:d:Nh",
		    long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'n':
      count = (unsigned long)atol(optarg);
      break;

    case 's':
      spoofed_addr = optarg;
      break;

    case 'p':
      port = atoi(optarg);
      break;

    case 'w':
      wait = optarg;
      wait_f = TRUE;
      break;

    case 'i':
      interval = optarg;
      break;

    case 'f':
      flowrec_count = atoi(optarg);
      break;

    case 'd':		/* XXX: make this optional arg */
      debug = atoi(optarg);
      break;

    case 'N':
      nosend_f = TRUE;
      break;

    case 'h':
      usage();
      break;

    case OPT_ENGINETYPE:
      engine_type = optarg;
      break;

    case OPT_ENGINEID:
      engine_id = optarg;
      break;

    case OPT_SRCADDR:
      src_addr = optarg;
      break;

    case OPT_DSTADDR:
      dst_addr = optarg;
      break;

    case OPT_NEXTHOP:
      nexthop = optarg;
      break;

    case OPT_INPUTIF:
      in_if = optarg;
      break;

    case OPT_OUTPUTIF:
      out_if = optarg;
      break;

    case OPT_PACKETS:
      packets = optarg;
      break;

    case OPT_OCTETS:
      octets = optarg;
      break;

    case OPT_FIRSTSEEN:
      first = optarg;
      break;

    case OPT_LASTSEEN:
      first = optarg;
      break;

    case OPT_SRCPORT:
      src_port = optarg;
      break;

    case OPT_DSTPORT:
      dst_port = optarg;
      break;

    case OPT_TCPFLAGS:
      tcp_flags = optarg;
      break;

    case OPT_PROTOCOL:
      proto = optarg;
      break;

    case OPT_TOS:
      tos = optarg;
      break;

    case OPT_SRCAS:
      src_as = optarg;
      break;

    case OPT_DSTAS:
      dst_as = optarg;
      break;

    case OPT_SRCMASK:
      src_mask = optarg;
      break;

    case OPT_DSTMASK:
      dst_mask = optarg;
      break;

    default:
      usage();
      /* NOTREACHED */
    }
  }

  argc -= optind;
  argv += optind;

  if (argc != 1)
    usage();

  if (1) {
    printf("collector = %s\n",  *argv);
    printf("count     = %lu\n", count);
    printf("spoof     = %s\n",  spoofed_addr ? spoofed_addr : "(none)");
    printf("port      = %d\n",  port);
    printf("wait      = %s (msec)\n",  wait);
    printf("interval  = %s\n",  interval);
    printf("flowrec   = %u\n",  flowrec_count);
    printf("debug     = %d\n",  debug);
    printf("eng_type  = %s\n",  engine_type);
    printf("eng_id    = %s\n",  engine_id);
    printf("src_addr  = %s\n",  src_addr);
    printf("dst_addr  = %s\n",  dst_addr);
    printf("nexthop   = %s\n",  nexthop);
    printf("in_if     = %s\n",  in_if);
    printf("out_if    = %s\n",  out_if);
    printf("packets   = %s\n",  packets);
    printf("ocetets   = %s\n",  octets);
    printf("first     = %s (msec)\n",  first);
    printf("last      = %s (msec)\n",  last);
    printf("src_port  = %s\n",  src_port);
    printf("dst_port  = %s\n",  dst_port);
    printf("tcpflags  = %s\n",  tcp_flags);
    printf("proto     = %s\n",  proto);
    printf("tos       = %s\n",  tos);
    printf("src_as    = %s\n",  src_as);
    printf("dst_as    = %s\n",  dst_as);
    printf("src_mask  = %s\n",  src_mask);
    printf("dst_mask  = %s\n",  dst_mask);
  }

  init_exporter(*argv, port, flowrec_count);

  compile_expr(wait, &wait_exp);
  compile_expr(interval, &intvl_exp);
  compile_expr(engine_type, &Ex.engine_type);
  compile_expr(engine_id, &Ex.engine_id);

  compile_ipaddr_expr(src_addr, &srcaddr_exp);
  compile_ipaddr_expr(dst_addr, &dstaddr_exp);
  compile_ipaddr_expr(nexthop,  &nhop_exp);

  compile_expr(in_if, &iif_exp);
  compile_expr(out_if, &oif_exp);
  compile_expr(packets, &pkt_exp);
  compile_expr(octets, &oct_exp);
  compile_expr(first, &fseen_exp);
  compile_expr(last, &lseen_exp);
  compile_expr(src_port, &srcp_exp);
  compile_expr(dst_port, &dstp_exp);
  compile_expr(tcp_flags, &tcpf_exp);
  compile_expr(proto, &proto_exp);
  compile_expr(tos, &tos_exp);
  compile_expr(src_as, &srcas_exp);
  compile_expr(dst_as, &dstas_exp);
  compile_expr(src_mask, &srcmask_exp);
  compile_expr(dst_mask, &dstmask_exp);

  while (1) {
    char ip_addr[sizeof("XXX.XXX.XXX.XXX")];

    memset(&fi, 0, sizeof(fi));		/* XXX init */

    expr_addr(ip_addr, &srcaddr_exp);
    inet_aton(ip_addr, &fi.src_addr);
    expr_addr(ip_addr, &dstaddr_exp);
    inet_aton(ip_addr, &fi.dst_addr);
    expr_addr(ip_addr, &nhop_exp);
    inet_aton(ip_addr, &fi.nexthop);
    fi.in_if     = (u_int16_t)expr_val(&iif_exp);
    fi.out_if    = (u_int16_t)expr_val(&oif_exp);
    fi.packets   = (u_int32_t)expr_val(&pkt_exp);
    fi.octets    = (u_int32_t)expr_val(&oct_exp);

    ut = sysuptime();
    fi.last      = ut - (u_int32_t)expr_val(&lseen_exp);
    fi.first     = fi.last - (u_int32_t)expr_val(&fseen_exp);

    fi.src_port  = (u_int16_t)expr_val(&srcp_exp);
    fi.dst_port  = (u_int16_t)expr_val(&dstp_exp);
    fi.tcp_flags = (u_int8_t)expr_val(&tcpf_exp);
    fi.ip_proto  = (u_int8_t)expr_val(&proto_exp);
    fi.tos       = (u_int8_t)expr_val(&tos_exp);
    fi.src_as    = (u_int16_t)expr_val(&srcas_exp);
    fi.dst_as    = (u_int16_t)expr_val(&dstas_exp);
    fi.src_mask  = (u_int8_t)expr_val(&srcmask_exp);
    fi.dst_mask  = (u_int8_t)expr_val(&dstmask_exp);

    add_flow(&fi);

    if (wait_f) {
      struct timespec req;
      unsigned long w;

      if ((n % expr_val(&intvl_exp)) == 0) {
	w = (unsigned long)expr_val(&wait_exp);
	req.tv_sec = (w * 1000 * 1000) / 1000000000;
	req.tv_nsec = (w * 1000 * 1000) % 1000000000;
	if (nanosleep(&req, NULL) == -1)
	  perror("nanosleep");
      }
    }

    n++;
    if (!count)
      continue;
    else if (n >= count)
      break;
  }

  flush_flow();

  if (debug)
    printf("%lu flow(s) generated\n", count);

  return 0;

}
