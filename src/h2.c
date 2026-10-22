#include "h2.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "ctl.h"
#include "gro.h"
#include "tlsx.h"
#include "util.h"

#define SNI "consumer-masque.cloudflareclient.com"
#define AUTHORITY "cloudflareaccess.com"
#define CONNECT_PROTOCOL "cf-connect-ip"
#define PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

#define CAPSULE_DATAGRAM 0
#define STREAM_ID 1

enum {
	FRAME_DATA = 0,
	FRAME_HEADERS = 1,
	FRAME_RST_STREAM = 3,
	FRAME_SETTINGS = 4,
	FRAME_PING = 6,
	FRAME_GOAWAY = 7,
	FRAME_WINDOW_UPDATE = 8
};

#define FLAG_ACK 0x01
#define FLAG_END_HEADERS 0x04

#define SETTING_HEADER_TABLE_SIZE 0x1
#define SETTING_ENABLE_PUSH 0x2
#define SETTING_INITIAL_WINDOW_SIZE 0x4
#define SETTING_MAX_FRAME_SIZE 0x5

#define WINDOW (8u << 20)
#define WINDOW_REFILL (32u << 10)
#define MAX_FRAME 16384

/* one per worker thread: every worker calls fail() on its own errors */
static __thread char error_buf[256];

/* Workers run one to a thread and all report into the same warp_status, so
 * every counter in it is touched concurrently. Relaxed ordering is enough:
 * these are statistics, nothing branches on them. */
#define COUNT_ADD(field, n) __atomic_fetch_add(&(field), (n), __ATOMIC_RELAXED)
#define COUNT_SUB(field, n) __atomic_fetch_sub(&(field), (n), __ATOMIC_RELAXED)

const char *h2_error(void)
{
	return error_buf;
}

static int fail(const char *fmt, const char *detail)
{
	snprintf(error_buf, sizeof(error_buf), fmt, detail ? detail : "");
	return -1;
}

/* `head` is how much of the front has already been consumed. Draining only
 * moves that cursor, so taking a frame off the inbox costs nothing; the buffer
 * is compacted once, lazily, when an append actually needs the room back.
 * Draining used to memmove the whole remainder every frame, which on a full
 * 8 MiB receive window meant shifting megabytes per 16 KiB frame. */
struct buf {
	uint8_t *data;
	size_t head;
	size_t len;
	size_t cap;
};

#define BUF_PTR(b) ((b)->data + (b)->head)
#define BUF_LEN(b) ((b)->len - (b)->head)

static void buf_compact(struct buf *b)
{
	if (!b->head)
		return;
	if (b->head >= b->len) {
		b->head = b->len = 0;
		return;
	}
	memmove(b->data, b->data + b->head, b->len - b->head);
	b->len -= b->head;
	b->head = 0;
}

static int buf_append(struct buf *b, const void *data, size_t len)
{
	if (b->len + len > b->cap) {
		buf_compact(b);
		if (b->len + len > b->cap) {
			size_t cap = b->cap ? b->cap * 2 : 8192;
			uint8_t *grown;

			while (cap < b->len + len)
				cap *= 2;
			grown = realloc(b->data, cap);
			if (!grown)
				return -1;
			b->data = grown;
			b->cap = cap;
		}
	}
	memcpy(b->data + b->len, data, len);
	b->len += len;
	return 0;
}

static void buf_drain(struct buf *b, size_t len)
{
	b->head += len;
	if (b->head >= b->len)
		b->head = b->len = 0;
}

/* Claim len bytes at the tail and hand back a pointer to write them directly,
 * so a caller assembling several pieces pays one bounds check instead of one
 * per piece. Returns NULL if it cannot grow. */
static uint8_t *buf_reserve(struct buf *b, size_t len)
{
	uint8_t *at;

	if (b->len + len > b->cap) {
		buf_compact(b);
		if (b->len + len > b->cap) {
			size_t cap = b->cap ? b->cap * 2 : 8192;
			uint8_t *grown;

			while (cap < b->len + len)
				cap *= 2;
			grown = realloc(b->data, cap);
			if (!grown)
				return NULL;
			b->data = grown;
			b->cap = cap;
		}
	}
	at = b->data + b->len;
	b->len += len;
	return at;
}

static void buf_free(struct buf *b)
{
	free(b->data);
	memset(b, 0, sizeof(*b));
}

static size_t put_varint(uint8_t *out, uint64_t value)
{
	if (value < 0x40) {
		out[0] = (uint8_t)value;
		return 1;
	}
	if (value < 0x4000) {
		out[0] = (uint8_t)(0x40 | (value >> 8));
		out[1] = (uint8_t)value;
		return 2;
	}
	if (value < 0x40000000) {
		out[0] = (uint8_t)(0x80 | (value >> 24));
		out[1] = (uint8_t)(value >> 16);
		out[2] = (uint8_t)(value >> 8);
		out[3] = (uint8_t)value;
		return 4;
	}
	out[0] = (uint8_t)(0xc0 | (value >> 56));
	out[1] = (uint8_t)(value >> 48);
	out[2] = (uint8_t)(value >> 40);
	out[3] = (uint8_t)(value >> 32);
	out[4] = (uint8_t)(value >> 24);
	out[5] = (uint8_t)(value >> 16);
	out[6] = (uint8_t)(value >> 8);
	out[7] = (uint8_t)value;
	return 8;
}

static int get_varint(const uint8_t *in, size_t len, uint64_t *value, size_t *used)
{
	size_t need, i;

	if (!len)
		return -1;
	need = (size_t)1 << (in[0] >> 6);
	if (len < need)
		return -1;
	*value = in[0] & 0x3f;
	for (i = 1; i < need; i++)
		*value = (*value << 8) | in[i];
	*used = need;
	return 0;
}

static size_t hpack_named(uint8_t *out, uint8_t index, const char *value)
{
	size_t len = strlen(value);

	out[0] = index;
	out[1] = (uint8_t)len;
	memcpy(out + 2, value, len);
	return len + 2;
}

static size_t hpack_pair(uint8_t *out, const char *name, const char *value)
{
	size_t name_len = strlen(name), value_len = strlen(value);

	out[0] = 0;
	out[1] = (uint8_t)name_len;
	memcpy(out + 2, name, name_len);
	out[2 + name_len] = (uint8_t)value_len;
	memcpy(out + 3 + name_len, value, value_len);
	return name_len + value_len + 3;
}

static size_t connect_headers(uint8_t *out)
{
	size_t len = 0;

	len += hpack_named(out + len, 1, AUTHORITY);
	len += hpack_named(out + len, 2, "CONNECT");
	len += hpack_pair(out + len, "capsule-protocol", "?1");
	len += hpack_pair(out + len, "cf-connect-proto", CONNECT_PROTOCOL);
	len += hpack_pair(out + len, "pq-enabled", "false");
	len += hpack_pair(out + len, "user-agent", "");
	return len;
}

static int hpack_integer(const uint8_t *block, size_t len, size_t *pos,
			 int prefix_bits, uint64_t *value)
{
	uint64_t max = ((uint64_t)1 << prefix_bits) - 1;
	int shift = 0;

	if (*pos >= len)
		return -1;
	*value = block[(*pos)++] & max;
	if (*value < max)
		return 0;
	for (;;) {
		uint8_t byte;

		if (*pos >= len)
			return -1;
		byte = block[(*pos)++];
		*value += (uint64_t)(byte & 0x7f) << shift;
		if (!(byte & 0x80))
			return 0;
		shift += 7;
	}
}

static int hpack_status(const uint8_t *block, size_t len)
{
	static const struct { uint8_t index; int code; } STATIC_STATUS[] = {
		{ 8, 200 }, { 9, 204 }, { 10, 206 }, { 11, 304 },
		{ 12, 400 }, { 13, 404 }, { 14, 500 }
	};
	size_t pos = 0;

	while (pos < len) {
		uint8_t first = block[pos];
		uint64_t index = 0, value_len = 0;
		int is_status = 0, huffman;
		size_t i;

		if (first & 0x80) {
			if (hpack_integer(block, len, &pos, 7, &index))
				return -1;
			for (i = 0; i < sizeof(STATIC_STATUS) / sizeof(*STATIC_STATUS); i++)
				if (STATIC_STATUS[i].index == index)
					return STATIC_STATUS[i].code;
			continue;
		}
		if ((first & 0xe0) == 0x20) {
			if (hpack_integer(block, len, &pos, 5, &index))
				return -1;
			continue;
		}
		if (hpack_integer(block, len, &pos, (first & 0x40) ? 6 : 4, &index))
			return -1;
		is_status = (index >= 8 && index <= 14);
		if (!index) {
			uint64_t name_len;

			if (pos >= len)
				return -1;
			huffman = block[pos] & 0x80;
			if (hpack_integer(block, len, &pos, 7, &name_len) || pos + name_len > len)
				return -1;
			is_status = !huffman && name_len == 7 &&
				    !memcmp(block + pos, ":status", 7);
			pos += name_len;
		}
		if (pos >= len)
			return -1;
		huffman = block[pos] & 0x80;
		if (hpack_integer(block, len, &pos, 7, &value_len) || pos + value_len > len)
			return -1;
		if (is_status && !huffman) {
			char text[8];

			if (value_len >= sizeof(text))
				return -1;
			memcpy(text, block + pos, value_len);
			text[value_len] = 0;
			return atoi(text);
		}
		pos += value_len;
	}
	return -1;
}

/* Hand-off between the two halves of a worker.
 *
 * Decrypting a TLS connection is strictly ordered -- record sequence numbers
 * see to that -- so it has to stay on one thread. Everything downstream of it
 * (HTTP/2 framing, capsule parsing, coalescing, the write to the TUN device)
 * does not, and on this hardware it costs about as much as the crypto. Passing
 * decrypted bytes across this ring lets the two run on separate cores, which
 * is the only way a single flow gets more than one core's worth of work done.
 * Order is preserved because the ring is strictly FIFO with one reader. */
#define CHAN_SLOT 131072
#define CHAN_SLOTS 4

struct chan {
	uint8_t buf[CHAN_SLOTS][CHAN_SLOT];
	size_t len[CHAN_SLOTS];
	unsigned head, tail, count;
	int closed;
	pthread_mutex_t lock;
	pthread_cond_t not_empty, not_full;
};

struct session {
	tls_conn tls;
	struct warp_status *status;
	int tun_fd;
	struct gro *gro;
	size_t vnet_hdr_len;
	int mtu;
	/* outbox is filled by the processing thread and drained by the TLS
	 * thread, so it is the one piece of shared mutable state. */
	pthread_mutex_t outbox_lock;
	struct buf sending;
	int connected;
	int requested;
	struct buf outbox;
	struct buf inbox;
	struct buf body;
	long long send_window;
	long long stream_window;
	unsigned unacked;
};

static void chan_init(struct chan *c)
{
	memset(c, 0, sizeof(*c));
	pthread_mutex_init(&c->lock, NULL);
	pthread_cond_init(&c->not_empty, NULL);
	pthread_cond_init(&c->not_full, NULL);
}

static void chan_destroy(struct chan *c)
{
	pthread_mutex_destroy(&c->lock);
	pthread_cond_destroy(&c->not_empty);
	pthread_cond_destroy(&c->not_full);
}

static void chan_close(struct chan *c)
{
	pthread_mutex_lock(&c->lock);
	c->closed = 1;
	pthread_cond_broadcast(&c->not_empty);
	pthread_cond_broadcast(&c->not_full);
	pthread_mutex_unlock(&c->lock);
}

/* Producer: claim the next free slot, or -1 once the channel is closed. */
static int chan_write_slot(struct chan *c)
{
	int idx;

	pthread_mutex_lock(&c->lock);
	while (c->count == CHAN_SLOTS && !c->closed)
		pthread_cond_wait(&c->not_full, &c->lock);
	idx = c->closed ? -1 : (int)c->tail;
	pthread_mutex_unlock(&c->lock);
	return idx;
}

static void chan_commit(struct chan *c, size_t len)
{
	pthread_mutex_lock(&c->lock);
	c->len[c->tail] = len;
	c->tail = (c->tail + 1) % CHAN_SLOTS;
	c->count++;
	pthread_cond_signal(&c->not_empty);
	pthread_mutex_unlock(&c->lock);
}

/* Consumer: next filled slot, or -1 when closed and drained. */
static int chan_read_slot(struct chan *c)
{
	int idx;

	pthread_mutex_lock(&c->lock);
	while (!c->count && !c->closed)
		pthread_cond_wait(&c->not_empty, &c->lock);
	idx = c->count ? (int)c->head : -1;
	pthread_mutex_unlock(&c->lock);
	return idx;
}

/* Is another slot already waiting? Used to decide whether a coalesced run can
 * keep growing instead of being flushed immediately. */
static int chan_ready(struct chan *c)
{
	int n;

	pthread_mutex_lock(&c->lock);
	n = (int)c->count;
	pthread_mutex_unlock(&c->lock);
	return n;
}

static void chan_release(struct chan *c)
{
	pthread_mutex_lock(&c->lock);
	c->head = (c->head + 1) % CHAN_SLOTS;
	c->count--;
	pthread_cond_signal(&c->not_full);
	pthread_mutex_unlock(&c->lock);
}

static size_t frame_header(uint8_t *out, uint8_t kind, uint8_t flags, uint32_t stream, size_t len)
{
	out[0] = (uint8_t)(len >> 16);
	out[1] = (uint8_t)(len >> 8);
	out[2] = (uint8_t)len;
	out[3] = kind;
	out[4] = flags;
	out[5] = (uint8_t)(stream >> 24);
	out[6] = (uint8_t)(stream >> 16);
	out[7] = (uint8_t)(stream >> 8);
	out[8] = (uint8_t)stream;
	return 9;
}

static int queue_frame(struct session *s, uint8_t kind, uint8_t flags, uint32_t stream,
		       const void *payload, size_t len)
{
	uint8_t header[9];
	int rc;

	frame_header(header, kind, flags, stream, len);
	pthread_mutex_lock(&s->outbox_lock);
	rc = buf_append(&s->outbox, header, sizeof(header));
	if (!rc && len)
		rc = buf_append(&s->outbox, payload, len);
	pthread_mutex_unlock(&s->outbox_lock);
	return rc;
}

static int flush(struct session *s)
{
	/* Take the whole outbox in one swap so the processing thread is never
	 * blocked behind a TLS write. */
	if (!BUF_LEN(&s->sending)) {
		pthread_mutex_lock(&s->outbox_lock);
		if (BUF_LEN(&s->outbox)) {
			struct buf tmp = s->sending;

			s->sending = s->outbox;
			s->outbox = tmp;
			s->outbox.head = s->outbox.len = 0;
		}
		pthread_mutex_unlock(&s->outbox_lock);
	}
	while (BUF_LEN(&s->sending)) {
		int n = tls_write(&s->tls, BUF_PTR(&s->sending), BUF_LEN(&s->sending));

		if (n == TLS_WANT_IO)
			return 0;
		if (n < 0)
			return fail("%s", tls_error());
		buf_drain(&s->sending, (size_t)n);
	}
	return 0;
}

/* Parse capsules straight out of the caller's bytes and return how many were
 * consumed, so a DATA payload that holds whole capsules -- the common case --
 * never has to be copied into s->body first. Only a trailing partial capsule
 * gets buffered. */
static size_t parse_capsules(struct session *s, const uint8_t *data, size_t len)
{
	size_t pos = 0;

	for (;;) {
		uint64_t kind, capsule_len;
		size_t type_len, len_len, start, end, left = len - pos;

		if (get_varint(data + pos, left, &kind, &type_len))
			return pos;
		if (get_varint(data + pos + type_len, left - type_len, &capsule_len, &len_len))
			return pos;
		start = type_len + len_len;
		end = start + (size_t)capsule_len;
		if (left < end)
			return pos;
		if (kind == CAPSULE_DATAGRAM) {
			gro_push(s->gro, data + pos + start, (size_t)capsule_len);
			COUNT_ADD(s->status->rx_packets, 1);
			COUNT_ADD(s->status->rx_bytes, capsule_len);
		}
		pos += end;
	}
}

/* Feed a DATA payload through the capsule parser, buffering only a partial
 * tail. Anything already held in s->body has to be joined first to keep the
 * capsule stream contiguous. */
static int take_capsules(struct session *s, const uint8_t *payload, size_t len)
{
	size_t used;

	if (!BUF_LEN(&s->body)) {
		used = parse_capsules(s, payload, len);
		if (used < len && buf_append(&s->body, payload + used, len - used))
			return -1;
		return 0;
	}
	if (buf_append(&s->body, payload, len))
		return -1;
	used = parse_capsules(s, BUF_PTR(&s->body), BUF_LEN(&s->body));
	buf_drain(&s->body, used);
	return 0;
}

static int send_packet(struct session *s, const uint8_t *packet, size_t len)
{
	uint8_t capsule[16];
	size_t header_len = 0;
	long long cost;

	header_len += put_varint(capsule + header_len, CAPSULE_DATAGRAM);
	header_len += put_varint(capsule + header_len, len);
	cost = (long long)(header_len + len);

	/* Windows and the outbox are both shared with the processing thread. */
	pthread_mutex_lock(&s->outbox_lock);
	if (s->send_window < cost || s->stream_window < cost) {
		pthread_mutex_unlock(&s->outbox_lock);
		return 0;
	}
	s->send_window -= cost;
	s->stream_window -= cost;

	{
		uint8_t *out = buf_reserve(&s->outbox, 9 + header_len + len);

		if (!out) {
			pthread_mutex_unlock(&s->outbox_lock);
			return fail("out of memory%s", NULL);
		}
		frame_header(out, FRAME_DATA, 0, STREAM_ID, header_len + len);
		memcpy(out + 9, capsule, header_len);
		memcpy(out + 9 + header_len, packet, len);
		COUNT_ADD(s->status->tx_packets, 1);
		COUNT_ADD(s->status->tx_bytes, len);
	}
	pthread_mutex_unlock(&s->outbox_lock);
	return 0;
}

/* Parse HTTP/2 frames straight out of the caller's bytes and return how many
 * were consumed, so decrypted data holding whole frames never has to be copied
 * into s->inbox first. Returns -1 on a protocol error. */
static ssize_t parse_frames(struct session *s, const uint8_t *data, size_t total)
{
	size_t pos = 0;

	while (total - pos >= 9) {
		const uint8_t *raw = data + pos;
		size_t len = ((size_t)raw[0] << 16) | ((size_t)raw[1] << 8) | raw[2];
		uint8_t kind = raw[3];
		uint8_t flags = raw[4];
		uint32_t stream = ((uint32_t)raw[5] << 24 | (uint32_t)raw[6] << 16 |
				   (uint32_t)raw[7] << 8 | raw[8]) & 0x7fffffff;
		const uint8_t *payload = raw + 9;

		if (total - pos < 9 + len)
			return (ssize_t)pos;

		switch (kind) {
		case FRAME_SETTINGS:
			if (!(flags & FLAG_ACK)) {
				size_t i;

				for (i = 0; i + 6 <= len; i += 6) {
					uint16_t id = (uint16_t)(payload[i] << 8 | payload[i + 1]);
					uint32_t value = (uint32_t)payload[i + 2] << 24 |
							 (uint32_t)payload[i + 3] << 16 |
							 (uint32_t)payload[i + 4] << 8 |
							 payload[i + 5];

					if (id == SETTING_INITIAL_WINDOW_SIZE) {
						pthread_mutex_lock(&s->outbox_lock);
						s->stream_window = value;
						pthread_mutex_unlock(&s->outbox_lock);
					}
				}
				if (queue_frame(s, FRAME_SETTINGS, FLAG_ACK, 0, NULL, 0))
					return fail("out of memory%s", NULL);
				if (!s->requested) {
					uint8_t headers[512];
					size_t header_len = connect_headers(headers);
					uint32_t window = htonl(WINDOW);

					if (queue_frame(s, FRAME_HEADERS, FLAG_END_HEADERS,
							STREAM_ID, headers, header_len))
						return fail("out of memory%s", NULL);
					if (queue_frame(s, FRAME_WINDOW_UPDATE, 0, STREAM_ID,
							&window, sizeof(window)))
						return fail("out of memory%s", NULL);
					s->requested = 1;
				}
			}
			break;
		case FRAME_PING:
			if (!(flags & FLAG_ACK) &&
			    queue_frame(s, FRAME_PING, FLAG_ACK, 0, payload, len))
				return fail("out of memory%s", NULL);
			break;
		case FRAME_WINDOW_UPDATE:
			if (len >= 4) {
				long long add = ((long long)payload[0] << 24 |
						 (long long)payload[1] << 16 |
						 (long long)payload[2] << 8 |
						 payload[3]) & 0x7fffffff;

				pthread_mutex_lock(&s->outbox_lock);
				if (stream == 0)
					s->send_window += add;
				else
					s->stream_window += add;
				pthread_mutex_unlock(&s->outbox_lock);
			}
			break;
		case FRAME_HEADERS: {
			int status = hpack_status(payload, len);

			if (status == 200) {
				__atomic_store_n(&s->connected, 1, __ATOMIC_RELAXED);
				/* status->connected counts connected workers;
				 * ctl only tests it for non-zero. */
				COUNT_ADD(s->status->connected, 1);
				snprintf(s->status->cipher, sizeof(s->status->cipher),
					 "%s", tls_ciphersuite(&s->tls));
				fprintf(stderr, "tunnel up: CONNECT accepted (HTTP/2, %s)\n",
					tls_ciphersuite(&s->tls));
			} else if (status > 0) {
				char detail[16];

				snprintf(detail, sizeof(detail), "%d", status);
				return fail("proxy refused CONNECT: HTTP %s", detail);
			} else {
				return fail("proxy sent an unparsable response status%s", NULL);
			}
			break;
		}
		case FRAME_DATA:
			s->unacked += (unsigned)len;
			if (take_capsules(s, payload, len))
				return fail("out of memory%s", NULL);
			if (s->unacked >= WINDOW_REFILL) {
				uint32_t add = htonl(s->unacked);

				s->unacked = 0;
				if (queue_frame(s, FRAME_WINDOW_UPDATE, 0, 0, &add, sizeof(add)) ||
				    queue_frame(s, FRAME_WINDOW_UPDATE, 0, STREAM_ID, &add, sizeof(add)))
					return fail("out of memory%s", NULL);
			}
			break;
		case FRAME_GOAWAY:
			return fail("proxy sent GOAWAY%s", NULL);
		case FRAME_RST_STREAM: {
			char detail[16];
			unsigned code = len >= 4 ? ((unsigned)payload[0] << 24 |
						    (unsigned)payload[1] << 16 |
						    (unsigned)payload[2] << 8 | payload[3]) : 0;

			snprintf(detail, sizeof(detail), "%u", code);
			return fail("proxy reset the tunnel stream (error %s)", detail);
		}
		default:
			break;
		}
		pos += 9 + len;
	}
	return (ssize_t)pos;
}

/* Feed decrypted bytes to the frame parser, buffering only a partial tail. */
static int take_frames(struct session *s, const uint8_t *data, size_t len)
{
	ssize_t used;

	if (!BUF_LEN(&s->inbox)) {
		used = parse_frames(s, data, len);
		if (used < 0)
			return -1;
		if ((size_t)used < len &&
		    buf_append(&s->inbox, data + used, len - (size_t)used))
			return fail("out of memory%s", NULL);
		return 0;
	}
	if (buf_append(&s->inbox, data, len))
		return fail("out of memory%s", NULL);
	used = parse_frames(s, BUF_PTR(&s->inbox), BUF_LEN(&s->inbox));
	if (used < 0)
		return -1;
	buf_drain(&s->inbox, (size_t)used);
	return 0;
}

struct pipeline {
	struct session *s;
	struct chan *chan;
	volatile sig_atomic_t *stop;
	const tunnel_opts *opts;
	int tun_fd;
	volatile int done;
	int rc;
	pthread_t proc;
	pthread_t tun;
};

/* Consumes decrypted bytes: HTTP/2 framing, capsules, coalescing, TUN write. */
static void *proc_main(void *arg)
{
	struct pipeline *pl = arg;

	for (;;) {
		int idx = chan_read_slot(pl->chan);

		if (idx < 0)
			break;
		if (take_frames(pl->s, pl->chan->buf[idx], pl->chan->len[idx])) {
			pl->rc = -1;
			chan_release(pl->chan);
			break;
		}
		chan_release(pl->chan);
		/* Only push the coalesced run out once nothing more is waiting.
		 * Flushing per slot would end every run after a single TLS
		 * record, which is no coalescing at all. */
		if (!chan_ready(pl->chan) && gro_flush(pl->s->gro)) {
			pl->rc = fail("failed to write to the tunnel device%s", NULL);
			break;
		}
	}
	pl->done = 1;
	return NULL;
}

/* Feeds the outbox from the TUN device. */
static void *tun_main(void *arg)
{
	struct pipeline *pl = arg;
	size_t vnet = pl->s->vnet_hdr_len;
	size_t cap = (size_t)pl->opts->mtu + 64 + vnet;
	uint8_t *packet = malloc(cap);

	if (!packet) {
		pl->rc = fail("out of memory%s", NULL);
		pl->done = 1;
		return NULL;
	}

	while (!*pl->stop && !pl->done) {
		struct pollfd p;

		p.fd = pl->tun_fd;
		p.events = POLLIN;
		p.revents = 0;
		poll(&p, 1, 20);

		if (!__atomic_load_n(&pl->s->connected, __ATOMIC_RELAXED))
			continue;

		for (;;) {
			ssize_t len = read(pl->tun_fd, packet, cap);

			if (len <= (ssize_t)vnet)
				break;
			if (send_packet(pl->s, packet + vnet, (size_t)len - vnet)) {
				pl->rc = -1;
				pl->done = 1;
				break;
			}
		}
	}
	free(packet);
	return NULL;
}

int h2_run(const warp_config *config, int tun_fd, const tunnel_opts *opts,
	   volatile sig_atomic_t *stop, struct warp_status *status)
{
	struct session s;
	const char *host = opts->use_ipv6 && config->endpoint_v6[0] ?
			   config->endpoint_v6 : config->endpoint_v4;
	uint8_t settings[24];
	size_t settings_len = 0;
	static __thread struct chan ch;
	uint32_t window;
	int rc = 0;

	memset(&s, 0, sizeof(s));
	s.status = status;
	s.tun_fd = tun_fd;
	s.vnet_hdr_len = opts->vnet_hdr_len;
	s.gro = gro_new(tun_fd, opts->vnet_hdr_len, (size_t)opts->mtu);
	if (!s.gro)
		return fail("out of memory%s", NULL);
	s.mtu = opts->mtu;
	s.send_window = 65535;
	s.stream_window = 65535;

	/* The endpoint ignores SNI and is authenticated by pinning its public key
	 * (config->spki), not by name, so secure mode drops the SNI entirely: the
	 * endpoint still answers a nameless handshake with the pinned certificate,
	 * and the real host name never appears on the wire. Otherwise SNI carries
	 * the usual decoy name, which the endpoint also ignores. */
	if (tls_client(&s.tls, host, opts->port, opts->secure ? NULL : SNI, "h2",
		       config->key_der, config->key_len,
		       config->spki, config->spki_len, opts->mark))
		return fail("%s", tls_error());
	if (tls_set_nonblocking(&s.tls)) {
		tls_close(&s.tls);
		return fail("%s", tls_error());
	}

	chan_init(&ch);
	pthread_mutex_init(&s.outbox_lock, NULL);

#define PUT_SETTING(id, value)                                                 \
	do {                                                                   \
		settings[settings_len++] = (uint8_t)((id) >> 8);                \
		settings[settings_len++] = (uint8_t)(id);                       \
		settings[settings_len++] = (uint8_t)((value) >> 24);            \
		settings[settings_len++] = (uint8_t)((value) >> 16);            \
		settings[settings_len++] = (uint8_t)((value) >> 8);             \
		settings[settings_len++] = (uint8_t)(value);                    \
	} while (0)
	PUT_SETTING(SETTING_HEADER_TABLE_SIZE, 0);
	PUT_SETTING(SETTING_ENABLE_PUSH, 0);
	PUT_SETTING(SETTING_INITIAL_WINDOW_SIZE, WINDOW);
	PUT_SETTING(SETTING_MAX_FRAME_SIZE, MAX_FRAME);
#undef PUT_SETTING

	window = htonl(WINDOW);
	if (buf_append(&s.outbox, PREFACE, sizeof(PREFACE) - 1) ||
	    queue_frame(&s, FRAME_SETTINGS, 0, 0, settings, settings_len) ||
	    queue_frame(&s, FRAME_WINDOW_UPDATE, 0, 0, &window, sizeof(window)))
		rc = fail("out of memory%s", NULL);

	/* Pipeline: this thread owns the TLS connection and does nothing but
	 * decrypt into the ring and encrypt out of the outbox. A second thread
	 * drains the ring (framing, capsules, coalescing, the TUN write) and a
	 * third feeds the outbox from the TUN device. Splitting them is what
	 * lets a single flow use more than one core. */
	{
		struct pipeline pl;

		pl.s = &s;
		pl.chan = &ch;
		pl.stop = stop;
		pl.opts = opts;
		pl.tun_fd = tun_fd;
		pl.done = 0;
		pl.rc = 0;

		if (pthread_create(&pl.proc, NULL, proc_main, &pl)) {
			rc = fail("could not start the processing thread%s", NULL);
		} else if (pthread_create(&pl.tun, NULL, tun_main, &pl)) {
			pl.done = 1;
			chan_close(&ch);
			pthread_join(pl.proc, NULL);
			rc = fail("could not start the tunnel reader%s", NULL);
		} else {
			while (!rc && !*stop && !pl.done) {
				struct pollfd fds[2];
				int count, pending;

				if (flush(&s)) {
					rc = -1;
					break;
				}

				for (;;) {
					int slot = chan_write_slot(&ch);
					size_t filled = 0;
					int done = 0;

					if (slot < 0)
						break;
					/* Pack as many records as will fit before
					 * handing the slot over. One record per
					 * slot would leave the coalescer with a
					 * single packet to work with each time. */
					while (CHAN_SLOT - filled >= MAX_FRAME + 512) {
						int n = tls_read(&s.tls, ch.buf[slot] + filled,
								 CHAN_SLOT - filled);

						if (n == TLS_WANT_IO) {
							done = 1;
							break;
						}
						if (n == 0) {
							rc = fail("connection closed by peer%s",
								  NULL);
							done = 1;
							break;
						}
						if (n < 0) {
							rc = fail("%s", tls_error());
							done = 1;
							break;
						}
						filled += (size_t)n;
					}
					if (filled)
						chan_commit(&ch, filled);
					if (done || rc)
						break;
				}
				if (rc)
					break;

				pthread_mutex_lock(&s.outbox_lock);
				pending = BUF_LEN(&s.outbox) != 0;
				pthread_mutex_unlock(&s.outbox_lock);

				fds[0].fd = s.tls.fd;
				fds[0].events = POLLIN |
						((pending || BUF_LEN(&s.sending)) ? POLLOUT : 0);
				fds[0].revents = 0;
				count = 1;
				if (opts->ctl_fd >= 0) {
					fds[1].fd = opts->ctl_fd;
					fds[1].events = POLLIN;
					fds[1].revents = 0;
					count = 2;
				}
				poll(fds, (nfds_t)count, 20);

				if (count == 2 && (fds[1].revents & POLLIN) &&
				    ctl_serve(opts->ctl_fd, status))
					*stop = 1;
			}

			pl.done = 1;
			chan_close(&ch);
			pthread_join(pl.proc, NULL);
			pthread_join(pl.tun, NULL);
			if (!rc && pl.rc)
				rc = pl.rc;
		}
	}

	if (s.connected)
		COUNT_SUB(status->connected, 1);
	gro_free(s.gro);
	chan_destroy(&ch);
	pthread_mutex_destroy(&s.outbox_lock);
	buf_free(&s.sending);
	buf_free(&s.outbox);
	buf_free(&s.inbox);
	buf_free(&s.body);
	tls_close(&s.tls);
	return rc;
}
