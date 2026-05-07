#define _GNU_SOURCE

#include "unprivileged.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
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

#define UNPRIVILEGED_TIMEOUT_MS 1000

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

static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t recv_ready_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t **seen = NULL;
static cachehash *ch = NULL;
static volatile int stop_unprivileged_scan = 0;

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

static int wait_for_fd(int fd, short events, int timeout_ms)
{
	struct pollfd pfd = {.fd = fd, .events = events, .revents = 0};
	int ret;
	do {
		ret = poll(&pfd, 1, timeout_ms);
	} while (ret < 0 && errno == EINTR);
	return ret;
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return -1;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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

static int run_tcp_connect_probe(uint32_t src_ip, uint32_t dst_ip,
				 uint16_t dst_port, int probe_num,
				 uint32_t *validation)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	struct linger linger = {.l_onoff = 1, .l_linger = 0};
	(void)setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));

	uint16_t num_source_ports =
	    zconf.source_port_last - zconf.source_port_first + 1;
	uint16_t local_port =
	    get_src_port(num_source_ports, probe_num, validation);
	struct sockaddr_in local = {.sin_family = AF_INET,
				    .sin_port = htons(local_port),
				    .sin_addr.s_addr = src_ip};
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		close(fd);
		return -1;
	}
	if (set_nonblocking(fd) < 0) {
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
		if (connect_errno == EINPROGRESS) {
			rc = wait_for_fd(fd, POLLOUT, UNPRIVILEGED_TIMEOUT_MS);
			if (rc > 0) {
				socklen_t optlen = sizeof(connect_errno);
				if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
					       &connect_errno, &optlen) < 0) {
					connect_errno = errno;
				}
			} else if (rc == 0) {
				connect_errno = ETIMEDOUT;
			} else {
				connect_errno = errno;
			}
		}
	} else {
		connect_errno = 0;
	}

	if (connect_errno == 0 || connect_errno == EISCONN ||
	    connect_errno == ECONNREFUSED) {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		fieldset_t *fs = fs_new_fieldset(&zconf.fsconf.defs);
		struct ip ip;
		init_synthetic_ip(&ip, IPPROTO_TCP, dst_ip, src_ip,
				  sizeof(struct ip));
		fs_add_ip_fields(fs, &ip);
		add_tcp_result_fields(fs, dst_port, local_port,
				      connect_errno == 0 || connect_errno == EISCONN);
		finalize_fieldset(fs, dst_ip, dst_port, ts);
		fs_free(fs);
	}
	close(fd);
	if (connect_errno == 0 || connect_errno == EISCONN ||
	    connect_errno == ECONNREFUSED || connect_errno == ETIMEDOUT) {
		return 0;
	}
	return -1;
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
	double send_rate = (double)zconf.rate / (double)zconf.senders;
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
			if (backend == UNPRIV_BACKEND_TCP_CONNECT) {
				rc = run_tcp_connect_probe(src_ip, current_ip,
							   current_port,
							   probe_num,
							   validation);
			} else if (backend == UNPRIV_BACKEND_UDP) {
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
	return EXIT_SUCCESS;
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
