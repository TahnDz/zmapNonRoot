#define _GNU_SOURCE

#include "unprivileged.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../lib/cachehash.h"
#include "../lib/logger.h"
#include "../lib/pbm.h"
#include "../lib/util.h"
#include "../lib/xalloc.h"

#include "expression.h"
#include "monitor.h"
#include "output_modules/output_modules.h"
#include "probe_modules/packet.h"
#include "probe_modules/probe_modules.h"
#include "send.h"
#include "shard.h"
#include "summary.h"
#include "state.h"
#include "validate.h"

#define UNPRIVILEGED_TIMEOUT_MS 200
#define TCP_CONNECT_PACING_SLICE_MS 10
#define TCP_CONNECT_MAX_LAUNCH_BATCH 8192
#define TCP_CONNECT_MAX_RATE_LAG_PACKETS 1024.0

typedef enum {
	UNPRIV_BACKEND_UNSUPPORTED = 0,
	UNPRIV_BACKEND_TCP_CONNECT,
	UNPRIV_BACKEND_UDP,
} unpriv_backend_t;

typedef struct unpriv_send_arg {
	uint32_t cpu;
	shard_t *shard;
} unpriv_send_arg_t;

typedef struct unpriv_mon_arg {
	uint32_t cpu;
	iterator_t *it;
	pthread_mutex_t *lock;
} unpriv_mon_arg_t;

typedef struct tcp_connect_probe {
	int fd;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint16_t local_port;
	double start_time;
} tcp_connect_probe_t;

static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t recv_ready_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t **seen = NULL;
static cachehash *ch = NULL;
static volatile int stop_unprivileged_scan = 0;

static void init_synthetic_ip(struct ip *ip, uint8_t proto, uint32_t src_ip,
			      uint32_t dst_ip, uint16_t ip_len);
static void finalize_fieldset(fieldset_t *fs, uint32_t src_ip,
			      uint16_t src_port, const struct timespec ts);

static unpriv_backend_t get_backend(void)
{
	const char *name = zconf.probe_module->name;
	if (!strcmp(name, "tcp_synscan")) {
		return UNPRIV_BACKEND_TCP_CONNECT;
	}
	if (!strcmp(name, "udp") || !strcmp(name, "dns") ||
	    !strcmp(name, "ntp") || !strcmp(name, "upnp") ||
	    !strcmp(name, "bacnet")) {
		return UNPRIV_BACKEND_UDP;
	}
	return UNPRIV_BACKEND_UNSUPPORTED;
}

bool unprivileged_module_supported(void)
{
	return get_backend() != UNPRIV_BACKEND_UNSUPPORTED;
}

static inline ipaddr_n_t get_src_ip_unprivileged(ipaddr_n_t dst,
						 int local_offset)
{
	if (zconf.number_source_ips == 1) {
		return zconf.source_ip_addresses[0];
	}
	return zconf.source_ip_addresses[(ntohl(dst) + local_offset) %
					 zconf.number_source_ips];
}

static void add_tcp_result_fields(fieldset_t *fs, uint16_t remote_port,
				      uint16_t local_port, int is_success)
{
	fs_add_uint64(fs, "sport", (uint64_t)remote_port);
	fs_add_uint64(fs, "dport", (uint64_t)local_port);
	fs_add_null(fs, "seqnum");
	fs_add_null(fs, "acknum");
	fs_add_null(fs, "window");
	fs_add_null(fs, "tcpopt_mss");
	fs_add_null(fs, "tcpopt_wscale");
	fs_add_null(fs, "tcpopt_sack_perm");
	fs_add_null(fs, "tcpopt_ts_val");
	fs_add_null(fs, "tcpopt_ts_ecr");
	fs_add_constchar(fs, "classification",
			 is_success ? "synack" : "rst");
	fs_add_bool(fs, "success", is_success);
	fs_add_null_icmp(fs);
}

static void emit_tcp_connect_result(uint32_t src_ip, uint32_t dst_ip,
					    uint16_t dst_port,
					    uint16_t local_port,
					    int is_success,
					    const struct timespec ts)
{
	fieldset_t *fs = fs_new_fieldset(&zconf.fsconf.defs);
	struct ip ip;
	init_synthetic_ip(&ip, IPPROTO_TCP, dst_ip, src_ip, sizeof(struct ip));
	fs_add_ip_fields(fs, &ip);
	add_tcp_result_fields(fs, dst_port, local_port, is_success);
	finalize_fieldset(fs, dst_ip, dst_port, ts);
	fs_free(fs);
}

static void init_synthetic_ip(struct ip *ip, uint8_t proto, uint32_t src_ip,
			      uint32_t dst_ip, uint16_t ip_len)
{
	memset(ip, 0, sizeof(*ip));
	ip->ip_hl = 5;
	ip->ip_v = 4;
	ip->ip_len = htons(ip_len);
	ip->ip_p = proto;
	ip->ip_src.s_addr = src_ip;
	ip->ip_dst.s_addr = dst_ip;
}

static void init_unprivileged_recv_state(void)
{
	if (zconf.dedup_method == DEDUP_METHOD_FULL) {
		seen = pbm_init();
	} else if (zconf.dedup_method == DEDUP_METHOD_WINDOW) {
		ch = cachehash_init(zconf.dedup_window_size, NULL);
	}
	if (zconf.default_mode) {
		log_info("recv",
			 "duplicate responses will be excluded from output");
		log_info("recv",
			 "unsuccessful responses will be excluded from output");
	} else {
		log_info(
		    "recv",
		    "duplicate responses will be passed to the output module");
		log_info(
		    "recv",
		    "unsuccessful responses will be passed to the output module");
	}
	pthread_mutex_lock(&recv_ready_mutex);
	zconf.recv_ready = 1;
	pthread_mutex_unlock(&recv_ready_mutex);
	zrecv.start = now();
	if (zconf.max_results == 0) {
		zconf.max_results = (uint64_t)-1;
	}
}

static void finalize_fieldset(fieldset_t *fs, uint32_t src_ip,
			      uint16_t src_port, const struct timespec ts)
{
	pthread_mutex_lock(&output_mutex);
	int is_repeat = 0;
	if (zconf.dedup_method == DEDUP_METHOD_FULL) {
		is_repeat = pbm_check(seen, ntohl(src_ip));
	} else if (zconf.dedup_method == DEDUP_METHOD_WINDOW) {
		target_t t = {.ip = src_ip, .port = src_port, .status = 0};
		if (cachehash_get(ch, &t, sizeof(target_t))) {
			is_repeat = 1;
		} else {
			cachehash_put(ch, &t, sizeof(target_t), (void *)1);
		}
	}
	fs_add_system_fields(fs, is_repeat, zsend.complete, ts);
	zrecv.pcap_recv++;
	zrecv.validation_passed++;

	int success_index = zconf.fsconf.success_index;
	int is_success = fs_get_uint64_by_index(fs, success_index);
	if (is_success) {
		zrecv.success_total++;
		if (!is_repeat) {
			zrecv.success_unique++;
			if (zconf.dedup_method == DEDUP_METHOD_FULL) {
				pbm_set(seen, ntohl(src_ip));
			}
		}
		if (zsend.complete) {
			zrecv.cooldown_total++;
			if (!is_repeat) {
				zrecv.cooldown_unique++;
			}
		}
	} else {
		zrecv.failure_total++;
	}
	if (zconf.fsconf.app_success_index >= 0) {
		int is_app_success =
		    fs_get_uint64_by_index(fs, zconf.fsconf.app_success_index);
		if (is_app_success) {
			zrecv.app_success_total++;
			if (!is_repeat) {
				zrecv.app_success_unique++;
			}
		}
	}
	if (!is_success && zconf.default_mode) {
		pthread_mutex_unlock(&output_mutex);
		return;
	}
	if (is_repeat && zconf.default_mode) {
		pthread_mutex_unlock(&output_mutex);
		return;
	}
	if (!evaluate_expression(zconf.filter.expression, fs)) {
		pthread_mutex_unlock(&output_mutex);
		return;
	}
	zrecv.filter_success++;
	fieldset_t *translated =
	    translate_fieldset(fs, &zconf.fsconf.translation);
	if (zconf.output_module && zconf.output_module->process_ip) {
		zconf.output_module->process_ip(translated);
	}
	if (zconf.output_module && zconf.output_module->update &&
	    !(zrecv.success_unique % zconf.output_module->update_interval)) {
		zconf.output_module->update(&zconf, &zsend, &zrecv);
	}
	if (zconf.max_results && zrecv.filter_success >= zconf.max_results) {
		stop_unprivileged_scan = 1;
	}
	free(translated);
	pthread_mutex_unlock(&output_mutex);
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return -1;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int get_tcp_max_inflight(void)
{
	struct rlimit lim;
	rlim_t soft_limit = 1024;
	if (getrlimit(RLIMIT_NOFILE, &lim) == 0) {
		soft_limit = (lim.rlim_cur > 0) ? lim.rlim_cur : lim.rlim_max;
	}
	rlim_t per_thread = (soft_limit * 3) / 4 / zconf.senders;
	if (per_thread <= 64) {
		return 64;
	}
	if (per_thread > 65536) {
		per_thread = 65536;
	}
	return (int)per_thread;
}

static double get_tcp_effective_rate(double send_rate, int max_inflight)
{
	double max_rate = ((double)max_inflight * 1000.0) /
			  (double)UNPRIVILEGED_TIMEOUT_MS;
	if (max_rate < 1.0) {
		max_rate = 1.0;
	}
	if (send_rate <= 0.0) {
		return max_rate;
	}
	return send_rate;
}

static int get_tcp_launch_batch_cap(double send_rate)
{
	double batch = send_rate * ((double)TCP_CONNECT_PACING_SLICE_MS / 1000.0);
	int cap = (int)batch;
	if ((double)cap < batch) {
		cap++;
	}
	if (cap < 1) {
		cap = 1;
	}
	if (cap > TCP_CONNECT_MAX_LAUNCH_BATCH) {
		cap = TCP_CONNECT_MAX_LAUNCH_BATCH;
	}
	return cap;
}

static int time_until_next_send_ms(double next_send_at)
{
	double now_time = steady_now();
	if (next_send_at <= 0.0 || next_send_at <= now_time) {
		return 0;
	}
	double remaining = next_send_at - now_time;
	int timeout_ms = (int)(remaining * 1000.0);
	if (timeout_ms < 0) {
		return 0;
	}
	if (timeout_ms > UNPRIVILEGED_TIMEOUT_MS) {
		timeout_ms = UNPRIVILEGED_TIMEOUT_MS;
	}
	return timeout_ms;
}

static int compute_tcp_poll_timeout(const tcp_connect_probe_t *probes,
					    int max_inflight,
					    int launches_pending,
					    double next_send_at)
{
	int timeout_ms = launches_pending ? time_until_next_send_ms(next_send_at)
					  : UNPRIVILEGED_TIMEOUT_MS;
	double now_time = steady_now();
	for (int i = 0; i < max_inflight; i++) {
		if (probes[i].fd < 0) {
			continue;
		}
		double age = now_time - probes[i].start_time;
		int remaining =
		    UNPRIVILEGED_TIMEOUT_MS - (int)(age * 1000.0);
		if (remaining < 0) {
			remaining = 0;
		}
		if (remaining < timeout_ms) {
			timeout_ms = remaining;
		}
	}
	return timeout_ms;
}

static int tcp_target_allowed(target_t current)
{
	return !zconf.list_of_ips_filename ||
	       pbm_check(zsend.list_of_ips_pbm, current.ip);
}

static target_t next_allowed_target(shard_t *s, target_t current)
{
	while (current.status != ZMAP_SHARD_DONE && !tcp_target_allowed(current)) {
		current = shard_get_next_target(s);
	}
	return current;
}

static int tcp_launch_rate_ready(double *next_send_at, double send_rate)
{
	if (send_rate <= 0) {
		return 1;
	}
	double now_time = steady_now();
	double max_lag = (double)TCP_CONNECT_PACING_SLICE_MS / 1000.0;
	double lag_for_packets =
	    TCP_CONNECT_MAX_RATE_LAG_PACKETS / send_rate;
	if (lag_for_packets > max_lag) {
		max_lag = lag_for_packets;
	}
	if (*next_send_at <= 0.0) {
		*next_send_at = now_time;
	}
	if (*next_send_at + max_lag < now_time) {
		*next_send_at = now_time;
	}
	if (now_time + 0.000001 < *next_send_at) {
		return 0;
	}
	*next_send_at += 1.0 / send_rate;
	return 1;
}

static int get_local_socket_port(int fd, uint16_t *port)
{
	struct sockaddr_in local;
	socklen_t local_len = sizeof(local);
	if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
		return -1;
	}
	*port = ntohs(local.sin_port);
	return 0;
}

// Send RST on close to avoid TIME_WAIT (60s), freeing the port immediately.
static void set_no_timewait(int fd)
{
	struct linger ling = {.l_onoff = 1, .l_linger = 0};
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
}

static void close_tcp_probe(tcp_connect_probe_t *probe, struct pollfd *pfd)
{
	if (probe->fd >= 0) {
		set_no_timewait(probe->fd);
		close(probe->fd);
	}
	probe->fd = -1;
	pfd->fd = -1;
	pfd->events = 0;
	pfd->revents = 0;
}

static int finalize_tcp_probe(tcp_connect_probe_t *probe, struct pollfd *pfd,
				      int connect_errno)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	if (connect_errno == 0 || connect_errno == EISCONN) {
		emit_tcp_connect_result(probe->src_ip, probe->dst_ip,
					probe->dst_port, probe->local_port, 1,
					ts);
	} else if (connect_errno == ECONNREFUSED) {
		emit_tcp_connect_result(probe->src_ip, probe->dst_ip,
					probe->dst_port, probe->local_port, 0,
					ts);
	}
	close_tcp_probe(probe, pfd);
	return (connect_errno == 0 || connect_errno == EISCONN ||
		connect_errno == ECONNREFUSED || connect_errno == ETIMEDOUT)
		   ? 0
		   : -1;
}

static void wait_for_rate(double send_rate, double *next_send_at)
{
	if (send_rate <= 0) {
		return;
	}
	double now_time = steady_now();
	if (*next_send_at <= 0.0) {
		*next_send_at = now_time;
	} else if (now_time < *next_send_at) {
		double sleep_for = *next_send_at - now_time;
		struct timespec ts;
		ts.tv_sec = (time_t)sleep_for;
		ts.tv_nsec = (long)((sleep_for - ts.tv_sec) * 1000000000.0);
		while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
		}
		now_time = steady_now();
	} else if (now_time - *next_send_at > 1.0) {
		*next_send_at = now_time;
	}
	*next_send_at += 1.0 / send_rate;
}

static void synthesize_udp_response(uint8_t *packet, size_t *packet_len,
				    const uint8_t *payload, size_t payload_len,
				    uint32_t remote_ip, uint16_t remote_port,
				    uint32_t local_ip, uint16_t local_port)
{
	memset(packet, 0, MAX_PACKET_SIZE);
	struct ether_header *eth = (struct ether_header *)packet;
	struct ip *ip = (struct ip *)(&eth[1]);
	struct udphdr *udp = (struct udphdr *)(&ip[1]);
	uint16_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) +
			  (uint16_t)payload_len;
	init_synthetic_ip(ip, IPPROTO_UDP, remote_ip, local_ip, ip_len);
	udp->uh_sport = htons(remote_port);
	udp->uh_dport = htons(local_port);
	udp->uh_ulen = htons(sizeof(struct udphdr) + payload_len);
	memcpy(&udp[1], payload, payload_len);
	*packet_len = sizeof(struct ether_header) + ip_len;
}

static void synthesize_udp_icmp_unreach(uint8_t *packet, size_t *packet_len,
					uint32_t remote_ip, uint32_t local_ip,
					uint16_t remote_port,
					uint16_t local_port)
{
	memset(packet, 0, MAX_PACKET_SIZE);
	struct ether_header *eth = (struct ether_header *)packet;
	struct ip *outer_ip = (struct ip *)(&eth[1]);
	struct icmp *icmp = (struct icmp *)(&outer_ip[1]);
	struct ip *inner_ip = (struct ip *)((char *)icmp + ICMP_HEADER_SIZE);
	struct udphdr *inner_udp = (struct udphdr *)(&inner_ip[1]);
	uint16_t inner_ip_len = sizeof(struct ip) + sizeof(struct udphdr);
	uint16_t outer_ip_len = sizeof(struct ip) + ICMP_HEADER_SIZE +
				sizeof(struct ip) + sizeof(struct udphdr);

	init_synthetic_ip(outer_ip, IPPROTO_ICMP, remote_ip, local_ip,
			  outer_ip_len);
	icmp->icmp_type = ICMP_UNREACH;
	icmp->icmp_code = ICMP_UNREACH_PORT;
	init_synthetic_ip(inner_ip, IPPROTO_UDP, local_ip, remote_ip,
			  inner_ip_len);
	inner_udp->uh_sport = htons(local_port);
	inner_udp->uh_dport = htons(remote_port);
	inner_udp->uh_ulen = htons(sizeof(struct udphdr));
	*packet_len = sizeof(struct ether_header) + outer_ip_len;
}

static int launch_tcp_connect_probe(tcp_connect_probe_t *probe,
					    struct pollfd *pfd,
					    uint32_t src_ip,
					    uint32_t dst_ip,
					    uint16_t dst_port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	// SO_REUSEADDR allows rebinding to the same source IP/port quickly
	int reuse = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	// SO_LINGER with linger=0 sends RST on close -> no 60s TIME_WAIT
	set_no_timewait(fd);
	// Boost buffers for high-throughput scanning
	int sndbuf = 1024 * 1024;
	int rcvbuf = 512 * 1024;
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
#ifdef TCP_SYNCNT
	int syn_retries = 1;
	(void)setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_retries,
			 sizeof(syn_retries));
#endif
	// TCP_NODELAY disables Nagle coalescing -> send immediately
	int nodelay = 1;
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

	struct sockaddr_in local = {.sin_family = AF_INET,
				    .sin_port = 0,
				    .sin_addr.s_addr = src_ip};
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		set_no_timewait(fd);
		close(fd);
		return -1;
	}
	if (set_nonblocking(fd) < 0) {
		set_no_timewait(fd);
		close(fd);
		return -1;
	}
	struct sockaddr_in remote = {.sin_family = AF_INET,
				     .sin_port = htons(dst_port),
				     .sin_addr.s_addr = dst_ip};
	int rc = connect(fd, (struct sockaddr *)&remote, sizeof(remote));
	int connect_errno = 0;
	if (rc < 0) {
		connect_errno = errno;
	} else {
		connect_errno = 0;
	}
	uint16_t local_port = 0;
	// Graceful: if getsockname fails, use port=0 and continue
	if (get_local_socket_port(fd, &local_port) < 0) {
		local_port = 0;
	}

	probe->fd = fd;
	probe->src_ip = src_ip;
	probe->dst_ip = dst_ip;
	probe->dst_port = dst_port;
	probe->local_port = local_port;
	probe->start_time = steady_now();
	pfd->fd = fd;
	pfd->events = POLLOUT | POLLERR | POLLHUP;
	pfd->revents = 0;

	if (connect_errno == EINPROGRESS || connect_errno == EALREADY ||
	    connect_errno == EWOULDBLOCK) {
		return 1;
	}
	return finalize_tcp_probe(probe, pfd, connect_errno);
}

static void reap_tcp_connect_probes(tcp_connect_probe_t *probes,
					    struct pollfd *pfds,
					    int max_inflight,
					    int launches_pending,
					    double next_send_at,
					    uint32_t *local_failures)
{
	int timeout_ms = compute_tcp_poll_timeout(probes, max_inflight,
						 launches_pending,
						 next_send_at);
	int ret;
	do {
		ret = poll(pfds, (nfds_t)max_inflight, timeout_ms);
	} while (ret < 0 && errno == EINTR);
	double now_time = steady_now();
	for (int i = 0; i < max_inflight; i++) {
		if (probes[i].fd < 0) {
			continue;
		}
		int connect_errno = -1;
		if (pfds[i].revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) {
			socklen_t optlen = sizeof(connect_errno);
			if (getsockopt(probes[i].fd, SOL_SOCKET, SO_ERROR,
				       &connect_errno, &optlen) < 0) {
				connect_errno = errno;
			}
		} else if ((now_time - probes[i].start_time) * 1000.0 >=
			   UNPRIVILEGED_TIMEOUT_MS) {
			connect_errno = ETIMEDOUT;
		}
		if (connect_errno == -1) {
			continue;
		}
		if (finalize_tcp_probe(&probes[i], &pfds[i], connect_errno) < 0) {
			(*local_failures)++;
		}
	}
}

static int run_tcp_connect_sender(shard_t *s, double send_rate)
{
	int max_inflight = get_tcp_max_inflight();
	double effective_rate = get_tcp_effective_rate(send_rate, max_inflight);
	int launch_batch_cap = get_tcp_launch_batch_cap(effective_rate);
	tcp_connect_probe_t *probes =
	    xcalloc((size_t)max_inflight, sizeof(tcp_connect_probe_t));
	struct pollfd *pfds =
	    xcalloc((size_t)max_inflight, sizeof(struct pollfd));
	for (int i = 0; i < max_inflight; i++) {
		probes[i].fd = -1;
		pfds[i].fd = -1;
	}

	double next_send_at = 0.0;
	target_t current = next_allowed_target(s, shard_get_cur_target(s));
	int probe_num = 0;
	int shard_done = (current.status == ZMAP_SHARD_DONE);
	int active_count = 0;

	while (!stop_unprivileged_scan &&
	       (!shard_done || active_count > 0)) {
		if (!shard_done && zconf.max_runtime &&
		    zconf.max_runtime <= now() - zsend.start) {
			shard_done = 1;
		}
		int launched_any = 0;
		int launched_this_round = 0;
		while (!stop_unprivileged_scan && !shard_done &&
		       active_count < max_inflight &&
		       launched_this_round < launch_batch_cap &&
		       tcp_launch_rate_ready(&next_send_at, effective_rate)) {
			if (zconf.max_runtime &&
			    zconf.max_runtime <= now() - zsend.start) {
				shard_done = 1;
				break;
			}
			if (s->state.max_targets &&
			    s->state.targets_scanned >= s->state.max_targets) {
				shard_done = 1;
				break;
			}
			int slot = -1;
			for (int i = 0; i < max_inflight; i++) {
				if (probes[i].fd < 0) {
					slot = i;
					break;
				}
			}
			if (slot < 0) {
				break;
			}
			uint32_t src_ip =
			    get_src_ip_unprivileged(current.ip, probe_num);
			int rc = launch_tcp_connect_probe(&probes[slot], &pfds[slot],
							  src_ip, current.ip,
							  current.port);
			if (rc < 0) {
				s->state.packets_failed++;
			} else if (rc > 0) {
				active_count++;
			}
			s->state.packets_sent++;
			launched_any = 1;
			launched_this_round++;

			probe_num++;
			if (probe_num >= zconf.probes_per_target) {
				probe_num = 0;
				s->state.targets_scanned++;
				current = next_allowed_target(
				    s, shard_get_next_target(s));
				shard_done = (current.status == ZMAP_SHARD_DONE);
			}
		}
		if (active_count > 0) {
			reap_tcp_connect_probes(probes, pfds, max_inflight,
						(!shard_done &&
						 active_count < max_inflight),
						next_send_at,
						&s->state.packets_failed);
			active_count = 0;
			for (int i = 0; i < max_inflight; i++) {
				if (probes[i].fd >= 0) {
					active_count++;
				}
			}
		} else if (!launched_any && !shard_done) {
			int timeout_ms = time_until_next_send_ms(next_send_at);
			if (timeout_ms > 0) {
				poll(NULL, 0, timeout_ms);
			}
		}
	}

	for (int i = 0; i < max_inflight; i++) {
		if (probes[i].fd >= 0) {
			close_tcp_probe(&probes[i], &pfds[i]);
		}
	}
	free(probes);
	free(pfds);
	return EXIT_SUCCESS;
}

static int run_udp_probe(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
			 int probe_num, uint32_t *validation, uint16_t ip_id,
			 void *probe_data, uint8_t *packet_template)
{
	uint8_t packet[MAX_PACKET_SIZE];
	memcpy(packet, packet_template, sizeof(packet));
	size_t packet_len = 0;
	int rc = zconf.probe_module->make_packet(
	    packet, &packet_len, src_ip, dst_ip, htons(dst_port),
	    zconf.probe_ttl, validation, probe_num, ip_id, probe_data);
	if (rc != EXIT_SUCCESS) {
		return -1;
	}
	struct ether_header *eth = (struct ether_header *)packet;
	struct ip *ip = (struct ip *)(&eth[1]);
	size_t ip_len = packet_len - sizeof(struct ether_header);
	struct udphdr *udp = get_udp_header(ip, ip_len);
	if (!udp) {
		return -1;
	}
	size_t payload_len = packet_len - sizeof(struct ether_header) -
			     ((size_t)ip->ip_hl * 4) - sizeof(struct udphdr);
	uint16_t local_port = ntohs(udp->uh_sport);
	uint8_t *payload = (uint8_t *)(&udp[1]);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}
	struct timeval timeout = {.tv_sec = UNPRIVILEGED_TIMEOUT_MS / 1000,
				  .tv_usec = (UNPRIVILEGED_TIMEOUT_MS % 1000) * 1000};
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	struct sockaddr_in local = {.sin_family = AF_INET,
				    .sin_port = htons(local_port),
				    .sin_addr.s_addr = src_ip};
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		close(fd);
		return -1;
	}
	struct sockaddr_in remote = {.sin_family = AF_INET,
				     .sin_port = htons(dst_port),
				     .sin_addr.s_addr = dst_ip};
	if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
		close(fd);
		return -1;
	}
	if (send(fd, payload, payload_len, 0) < 0) {
		close(fd);
		return -1;
	}

	uint8_t resp[MAX_PACKET_SIZE];
	ssize_t received = recv(fd, resp, sizeof(resp), 0);
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	if (received >= 0) {
		socklen_t local_len = sizeof(local);
		if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
			local.sin_addr.s_addr = src_ip;
			local.sin_port = htons(local_port);
		}
		uint8_t synthetic[MAX_PACKET_SIZE];
		size_t synthetic_len = 0;
		synthesize_udp_response(synthetic, &synthetic_len, resp,
					(size_t)received, dst_ip, dst_port,
					local.sin_addr.s_addr,
					ntohs(local.sin_port));
		fieldset_t *fs = fs_new_fieldset(&zconf.fsconf.defs);
		struct ip *resp_ip =
		    (struct ip *)(synthetic + sizeof(struct ether_header));
		fs_add_ip_fields(fs, resp_ip);
		zconf.probe_module->process_packet(synthetic, synthetic_len, fs,
						   validation, ts);
		finalize_fieldset(fs, dst_ip, dst_port, ts);
		fs_free(fs);
		close(fd);
		return 0;
	}

	if (errno == ECONNREFUSED) {
		socklen_t local_len = sizeof(local);
		if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
			local.sin_addr.s_addr = src_ip;
			local.sin_port = htons(local_port);
		}
		uint8_t synthetic[MAX_PACKET_SIZE];
		size_t synthetic_len = 0;
		synthesize_udp_icmp_unreach(synthetic, &synthetic_len, dst_ip,
					    local.sin_addr.s_addr, dst_port,
					    ntohs(local.sin_port));
		fieldset_t *fs = fs_new_fieldset(&zconf.fsconf.defs);
		struct ip *outer_ip =
		    (struct ip *)(synthetic + sizeof(struct ether_header));
		fs_add_ip_fields(fs, outer_ip);
		zconf.probe_module->process_packet(synthetic, synthetic_len, fs,
						   validation, ts);
		finalize_fieldset(fs, dst_ip, 0, ts);
		fs_free(fs);
	}
	close(fd);
	return 0;
}

static int run_unprivileged_sender(shard_t *s)
{
	unpriv_backend_t backend = get_backend();
	double send_rate = (double)zconf.rate / (double)zconf.senders;
	int ret = EXIT_SUCCESS;
	if (backend == UNPRIV_BACKEND_TCP_CONNECT) {
		ret = run_tcp_connect_sender(s, send_rate);
		goto cleanup;
	}
	void *probe_data = NULL;
	uint8_t packet_template[MAX_PACKET_SIZE];
	memset(packet_template, 0, sizeof(packet_template));
	if (backend == UNPRIV_BACKEND_UDP) {
		if (zconf.probe_module->thread_initialize &&
		    zconf.probe_module->thread_initialize(&probe_data) !=
			EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
		if (zconf.probe_module->prepare_packet &&
		    zconf.probe_module->prepare_packet(packet_template,
						       zconf.hw_mac,
						       zconf.gw_mac,
						       probe_data) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
	}

	double next_send_at = 0.0;
	target_t current = shard_get_cur_target(s);
	uint32_t current_ip = current.ip;
	uint16_t current_port = current.port;

	if (zconf.list_of_ips_filename) {
		while (!pbm_check(zsend.list_of_ips_pbm, current_ip)) {
			current = shard_get_next_target(s);
			current_ip = current.ip;
			current_port = current.port;
			if (current.status == ZMAP_SHARD_DONE) {
				goto cleanup;
			}
		}
	}

	while (!stop_unprivileged_scan) {
		if (zconf.max_runtime &&
		    zconf.max_runtime <= now() - zsend.start) {
			break;
		}
		if (s->state.max_targets &&
		    s->state.targets_scanned >= s->state.max_targets) {
			break;
		}
		if (current.status == ZMAP_SHARD_DONE) {
			break;
		}
		for (int probe_num = 0; probe_num < zconf.probes_per_target;
		     probe_num++) {
			if (stop_unprivileged_scan) {
				goto cleanup;
			}
			wait_for_rate(send_rate, &next_send_at);
			uint32_t src_ip =
			    get_src_ip_unprivileged(current_ip, probe_num);
			uint8_t validation_words =
			    VALIDATE_BYTES / sizeof(uint32_t);
			uint32_t validation[VALIDATE_BYTES / sizeof(uint32_t)];
			validate_gen(src_ip, current_ip, htons(current_port),
				     (uint8_t *)validation);
			uint16_t ip_id =
			    (uint16_t)(validation[validation_words - 1] & 0xFFFF);

			int rc = 0;
			if (backend == UNPRIV_BACKEND_UDP) {
				rc = run_udp_probe(src_ip, current_ip,
						   current_port, probe_num,
						   validation, ip_id,
						   probe_data,
						   packet_template);
			} else {
				return EXIT_FAILURE;
			}
			if (rc < 0) {
				s->state.packets_failed++;
			}
			s->state.packets_sent++;
		}
		s->state.targets_scanned++;
		current = shard_get_next_target(s);
		current_ip = current.ip;
		current_port = current.port;
		if (zconf.list_of_ips_filename &&
		    current.status != ZMAP_SHARD_DONE) {
			while (!pbm_check(zsend.list_of_ips_pbm, current_ip)) {
				current = shard_get_next_target(s);
				current_ip = current.ip;
				current_port = current.port;
				if (current.status == ZMAP_SHARD_DONE) {
					goto cleanup;
				}
			}
		}
	}

cleanup:
	s->cb(s->thread_id, s->arg);
	return ret;
}

static void *start_unprivileged_sender(void *arg)
{
	unpriv_send_arg_t *send_arg = (unpriv_send_arg_t *)arg;
	set_cpu(send_arg->cpu);
	int ret = run_unprivileged_sender(send_arg->shard);
	free(send_arg);
	if (ret != EXIT_SUCCESS) {
		log_fatal("unprivileged", "sender thread failed");
	}
	return NULL;
}

static void *start_unprivileged_monitor(void *arg)
{
	unpriv_mon_arg_t *mon_arg = (unpriv_mon_arg_t *)arg;
	set_cpu(mon_arg->cpu);
	monitor_run(mon_arg->it, mon_arg->lock);
	free(mon_arg);
	return NULL;
}

void start_unprivileged_scan(iterator_t *it)
{
	if (!unprivileged_module_supported()) {
		log_fatal("unprivileged", "unsupported probe module: %s",
			  zconf.probe_module->name);
	}
	stop_unprivileged_scan = 0;
	init_unprivileged_recv_state();

	pthread_t *tsend = xmalloc(zconf.senders * sizeof(pthread_t));
	pthread_t tmon;
	uint32_t cpu = 0;
	int monitor_thread_started =
	    (!zconf.quiet || zconf.status_updates_file);

	for (uint8_t i = 0; i < zconf.senders; i++) {
		unpriv_send_arg_t *arg = xmalloc(sizeof(unpriv_send_arg_t));
		arg->shard = get_shard(it, i);
		arg->cpu = zconf.pin_cores[cpu % zconf.pin_cores_len];
		cpu += 1;
		if (pthread_create(&tsend[i], NULL, start_unprivileged_sender,
				   arg) != 0) {
			log_fatal("unprivileged",
				  "unable to create sender thread");
		}
	}

	if (monitor_thread_started) {
		monitor_init();
		unpriv_mon_arg_t *mon_arg =
		    xmalloc(sizeof(unpriv_mon_arg_t));
		mon_arg->it = it;
		mon_arg->lock = &recv_ready_mutex;
		mon_arg->cpu = zconf.pin_cores[cpu % zconf.pin_cores_len];
		if (pthread_create(&tmon, NULL, start_unprivileged_monitor,
				   mon_arg) != 0) {
			log_fatal("unprivileged",
				  "unable to create monitor thread");
		}
	}

	for (uint8_t i = 0; i < zconf.senders; i++) {
		if (pthread_join(tsend[i], NULL) != 0) {
			log_fatal("unprivileged", "unable to join sender thread");
		}
	}
	zrecv.finish = now();
	zrecv.complete = 1;

	if (monitor_thread_started) {
		if (pthread_join(tmon, NULL) != 0) {
			log_fatal("unprivileged", "unable to join monitor thread");
		}
	}

	if (zconf.metadata_filename) {
		json_metadata(zconf.metadata_file);
	}
	if (zconf.output_module && zconf.output_module->close) {
		zconf.output_module->close(&zconf, &zsend, &zrecv);
	}
	if (zconf.probe_module && zconf.probe_module->close) {
		zconf.probe_module->close(&zconf, &zsend, &zrecv);
	}
	free(tsend);
	log_info("zmap", "completed");
}
