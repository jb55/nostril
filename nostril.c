
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_schnorrsig.h"

#include "cursor.h"
#include "hex.h"
#include "nip44.h"
#include "base64.h"
#include "aes.h"
#include "sha256.h"
#include "random.h"
#include "proof.h"

#define VERSION "0.1.3"

#define MAX_TAGS 1024
#define MAX_TAG_ELEMS 64

#define HAS_CREATED_AT (1<<1)
#define HAS_KIND (1<<2)
#define HAS_ENVELOPE (1<<3)
#define HAS_ENCRYPT (1<<4)
#define HAS_DIFFICULTY (1<<5)
#define HAS_MINE_PUBKEY (1<<6)
#define HAS_GIFTWRAP (1<<7)

struct key {
	secp256k1_keypair pair;
	unsigned char secret[32];
	unsigned char pubkey[32];
};

struct args {
	unsigned int flags;
	int kind;
	int difficulty;

	unsigned char encrypt_to[32];
	const char *sec;
	const char *tags;
	const char *content;

	uint64_t created_at;
};

struct nostr_tag {
	const char *strs[MAX_TAG_ELEMS];
	int num_elems;
};

struct nostr_event {
	unsigned char id[32];
	unsigned char pubkey[32];
	unsigned char sig[64];

	const char *content;

	uint64_t created_at;
	int kind;

	const char *explicit_tags;

	struct nostr_tag tags[MAX_TAGS];
	int num_tags;
};

void usage()
{
	printf("usage: nostril [OPTIONS]\n");
	printf("\n");
	printf("  OPTIONS\n");
	printf("\n");
	printf("      --content <string>              the content of the note\n");
	printf("      --dm <hex pubkey>               make an encrypted dm to said pubkey. sets kind and tags.\n");
	printf("      --giftwrap-to <hex pubkey>      make an encrypted giftwrap to said pubkey.\n");
	printf("      --envelope                      wrap in [\"EVENT\",...] for easy relaying\n");
	printf("      --kind <number>                 set kind\n");
	printf("      --created-at <unix timestamp>   set a specific created-at time\n");
	printf("      --sec <hex seckey>              set the secret key for signing, otherwise one will be randomly generated\n");
	printf("      --pow <difficulty>              number of leading 0 bits of the id to mine\n");
	printf("      --mine-pubkey                   mine a pubkey instead of id\n");
	printf("      --tag <key> <value>             add a tag\n");
	printf("      --tagn <N> <tags * N...>        add a tag with N elements. eg: `--tagn 3 a b c`, `--tagn 0`\n");
	printf("      -e <event_id>                   shorthand for --tag e <event_id>\n");
	printf("      -p <pubkey>                     shorthand for --tag p <pubkey>\n");
	printf("      -t <hashtag>                    shorthand for --tag t <hashtag>\n");
	exit(1);
}


inline static int cursor_push_escaped_char(struct cursor *cur, char c)
{
        switch (c) {
        case '"':  return cursor_push_str(cur, "\\\"");
        case '\\': return cursor_push_str(cur, "\\\\");
        case '\b': return cursor_push_str(cur, "\\b");
        case '\f': return cursor_push_str(cur, "\\f");
        case '\n': return cursor_push_str(cur, "\\n");
        case '\r': return cursor_push_str(cur, "\\r");
        case '\t': return cursor_push_str(cur, "\\t");
        // TODO: \u hex hex hex hex
        }
        return cursor_push_byte(cur, c);
}

static int cursor_push_jsonstr(struct cursor *cur, const char *str)
{
	int i;
        int len;

	len = strlen(str);

        if (!cursor_push_byte(cur, '"'))
                return 0;

        for (i = 0; i < len; i++) {
                if (!cursor_push_escaped_char(cur, str[i]))
                        return 0;
        }

        if (!cursor_push_byte(cur, '"'))
                return 0;

        return 1;
}

static int cursor_push_tag(struct cursor *cur, struct nostr_tag *tag)
{
        int i;

        if (!cursor_push_byte(cur, '['))
                return 0;

        for (i = 0; i < tag->num_elems; i++) {
                if (!cursor_push_jsonstr(cur, tag->strs[i]))
                        return 0;
                if (i != tag->num_elems-1) {
                        if (!cursor_push_byte(cur, ','))
                                return 0;
                }
        }

        return cursor_push_byte(cur, ']');
}

static int cursor_push_tags(struct cursor *cur, struct nostr_event *ev)
{
        int i;

	if (ev->explicit_tags) {
		return cursor_push_str(cur, ev->explicit_tags);
	}

        if (!cursor_push_byte(cur, '['))
                return 0;

        for (i = 0; i < ev->num_tags; i++) {
                if (!cursor_push_tag(cur, &ev->tags[i]))
                        return 0;
                if (i != ev->num_tags-1) {
                        if (!cursor_push_str(cur, ","))
                                return 0;
                }
        }

        return cursor_push_byte(cur, ']');
}


int event_commitment(struct nostr_event *ev, unsigned char *buf, int buflen)
{
	char timebuf[16] = {0};
	char kindbuf[16] = {0};
	char pubkey[65];
	struct cursor cur;
	int ok;

	ok = hex_encode(ev->pubkey, sizeof(ev->pubkey), pubkey, sizeof(pubkey));
	assert(ok);

	make_cursor(buf, buf + buflen, &cur);

	snprintf(timebuf, sizeof(timebuf), "%" PRIu64 "", ev->created_at);
        snprintf(kindbuf, sizeof(kindbuf), "%d", ev->kind);

	ok =
                cursor_push_str(&cur, "[0,\"") &&
                cursor_push_str(&cur, pubkey) &&
                cursor_push_str(&cur, "\",") &&
                cursor_push_str(&cur, timebuf) &&
                cursor_push_str(&cur, ",") &&
                cursor_push_str(&cur, kindbuf) &&
                cursor_push_str(&cur, ",") &&
                cursor_push_tags(&cur, ev) &&
                cursor_push_str(&cur, ",") &&
                cursor_push_jsonstr(&cur, ev->content) &&
                cursor_push_str(&cur, "]");

	if (!ok)
		return 0;

	return cur.p - cur.start;
}

static int make_sig(secp256k1_context *ctx, struct key *key,
		unsigned char *id, unsigned char sig[64])
{
	unsigned char aux[32];

	if (!fill_random(aux, sizeof(aux))) {
		return 0;
	}

	return secp256k1_schnorrsig_sign32(ctx, sig, id, &key->pair, aux);
}

static int create_key(secp256k1_context *ctx, struct key *key)
{
	secp256k1_xonly_pubkey pubkey;

	/* Try to create a keypair with a valid context, it should only
	 * fail if the secret key is zero or out of range. */
	if (!secp256k1_keypair_create(ctx, &key->pair, key->secret))
		return 0;

	if (!secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &key->pair))
		return 0;

	/* Serialize the public key. Should always return 1 for a valid public key. */
	return secp256k1_xonly_pubkey_serialize(ctx, key->pubkey, &pubkey);
}

static int decode_key(secp256k1_context *ctx, const char *secstr, struct key *key)
{
	if (!hex_decode(secstr, strlen(secstr), key->secret, 32)) {
		fprintf(stderr, "could not hex decode secret key\n");
		return 0;
	}

	return create_key(ctx, key);
}

static inline void xor_mix(unsigned char *dest, const unsigned char *a, const unsigned char *b, int size)
{
    int i;
    for (i = 0; i < size; i++)
        dest[i] = a[i] ^ b[i];
}

static int generate_key(secp256k1_context *ctx, struct key *key, int *difficulty)
{
	uint64_t attempts = 0;
	uint64_t duration;
	int bits;
	double pers;
	struct timespec t1, t2;

	/* If the secret key is zero or out of range (bigger than secp256k1's
	 * order), we try to sample a new key. Note that the probability of this
	 * happening is negligible. */
	if (!fill_random(key->secret, sizeof(key->secret))) {
		return 0;
	}

	if (difficulty == NULL) {
		return create_key(ctx, key);
	}

	clock_gettime(CLOCK_MONOTONIC, &t1);
	while (1) {
		if (!create_key(ctx, key))
			return 0;

		attempts++;

		if ((bits = count_leading_zero_bits(key->pubkey)) >= *difficulty) {
			clock_gettime(CLOCK_MONOTONIC, &t2);
			duration = ((t2.tv_sec - t1.tv_sec) * 1e9L + (t2.tv_nsec - t1.tv_nsec)) / 1e6L;
			pers = (double)attempts / (double)duration;
			fprintf(stderr, "mined pubkey with %d bits after %" PRIu64 " attempts, %" PRId64 " ms, %f attempts per ms\n", bits, attempts, duration, pers);
			return 1;
		}

		// NOTE: Get a new secret key by xor mixing the current secret
		// key with the current public key. This doesn't rely on the
		// system's crypto number generator so it should be fast. There
		// shouldn't be any secret key entropy issues since we got a
		// good source of entropy from the first fill_random call at
		// the start of the function.
		xor_mix(key->secret, key->secret, key->pubkey, 32);
	}
}


static int init_secp_context(secp256k1_context **ctx)
{
	unsigned char randomize[32];

	*ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	if (!fill_random(randomize, sizeof(randomize))) {
		return 0;
	}

	/* Randomizing the context is recommended to protect against side-channel
	 * leakage See `secp256k1_context_randomize` in secp256k1.h for more
	 * information about it. This should never fail. */
	return secp256k1_context_randomize(*ctx, randomize);
}

static int generate_event_id(struct nostr_event *ev,
			     unsigned char *buf, size_t bufsize)
{
	int len;

	if (!(len = event_commitment(ev, buf, bufsize))) {
		fprintf(stderr, "event_commitment: buffer out of space\n");
		return 0;
	}

	//fprintf(stderr, "commitment: '%.*s'\n", len, buf);

	sha256((struct sha256*)ev->id, buf, len);

	return 1;
}

static int sign_event(secp256k1_context *ctx, struct key *key, struct nostr_event *ev)
{
	if (!make_sig(ctx, key, ev->id, ev->sig))
		return 0;

	return 1;
}

static int all_zeros(unsigned char *buf, size_t bufsize)
{
	int i;

	for (i = 0; i < bufsize; i++) {
		if (buf[i] != 0)
			return 0;
	}

	return 1;
}

static int event_to_json(struct cursor *c, struct nostr_event *ev, int envelope)
{
	char shortbuf[128];

	if (envelope) {
		if (!cursor_push_str(c, "[\"EVENT\","))
			return 0;
	}

	if (!cursor_push_str(c, "{\"id\":\"")) return 0;
	if (!cursor_push_hex(c, ev->id, 32)) return 0;
	if (!cursor_push_str(c, "\",")) return 0;
	if (!cursor_push_str(c, "\"pubkey\":\"")) return 0;
	if (!cursor_push_hex(c, ev->pubkey, 32)) return 0;
	if (!cursor_push_str(c, "\",")) return 0;
	sprintf(shortbuf, "\"created_at\":%" PRIu64 ",", ev->created_at);
	if (!cursor_push_str(c, shortbuf)) return 0;
	sprintf(shortbuf, "\"kind\":%d,", ev->kind);
	if (!cursor_push_str(c, shortbuf)) return 0;
	if (!cursor_push_str(c, "\"tags\":")) return 0;
	if (!cursor_push_tags(c, ev)) return 0;
	if (!cursor_push_str(c, ",\"content\":")) return 0;
	if (!cursor_push_jsonstr(c, ev->content)) return 0;

	if (!all_zeros(ev->sig, 64)) {
		if (!cursor_push_str(c,  ",\"sig\":\"")) return 0;
		if (!cursor_push_hex(c,  ev->sig, 64)) return 0;
		if (!cursor_push_byte(c, '"')) return 0;
	}

	if (envelope) {
		if (!cursor_push_str(c, "]")) return 0;
	}

	return cursor_push_c_str(c, "}");
}

static int print_event(struct nostr_event *ev, int envelope,
		       unsigned char *buf, size_t bufsize)
{
	struct cursor cur;
	make_cursor(buf, buf+bufsize, &cur);

	if (!event_to_json(&cur, ev, envelope))
		return 0;

	printf("%s\n", buf);

	return 1;
}

static void make_event_from_args(struct nostr_event *ev, struct args *args)
{
	ev->created_at = args->flags & HAS_CREATED_AT? args->created_at : time(NULL);
	ev->content = args->content;
	ev->kind = args->flags & HAS_KIND ? args->kind : 1;
}

static int parse_num(const char *arg, uint64_t *t)
{
	*t = strtol(arg, NULL, 10);
	return errno != EINVAL;
}

static int nostr_add_tag_n(struct nostr_event *ev, const char **ts, int n_ts)
{
	int i;
	struct nostr_tag *tag;

	if (ev->num_tags + 1 > MAX_TAGS)
		return 0;

	tag = &ev->tags[ev->num_tags++];

	tag->num_elems = n_ts;
	for (i = 0; i < n_ts; i++) {
		tag->strs[i] = ts[i];
	}

	return 1;
}

static int nostr_add_tag(struct nostr_event *ev, const char *t1, const char *t2)
{
	const char *ts[] = {t1, t2};
	return nostr_add_tag_n(ev, ts, 2);
}

static int nostr_add_arg_tags(struct nostr_event *ev, int *argc, const char **argv[])
{
	struct nostr_tag *tag;
	int i;
	uint64_t n;
	uint16_t small_n;
	const char *arg;

	if (*argc == 0) {
		fprintf(stderr, "expected more arguments to --tagn\n");
		return 0;
	}

	arg = *(*argv)++; (*argc)--;

	if (!parse_num(arg, &n)) {
		fprintf(stderr, "expected X to be a number in --tagn X ...\n");
		return 0;
	}

	if (n > MAX_TAG_ELEMS) {
		fprintf(stderr, "too many --tagn arguments (%"PRIu64" > %d)\n", n, MAX_TAG_ELEMS);
		return 0;
	}

	small_n = (uint16_t)n;

	if (ev->num_tags + small_n > MAX_TAGS) {
		fprintf(stderr, "too many tags (%d + %d > %d)\n", ev->num_tags, small_n, MAX_TAG_ELEMS);
		return 0;
	}

	tag = &ev->tags[ev->num_tags++];
	tag->num_elems = 0;

	for (i = 0; i < small_n; i++) {
		if (*argc <= 0) {
			fprintf(stderr, "expected %d tags: --tagn %d ..., got %d args\n", small_n, small_n, i);
			return 0;
		}
		arg = *(*argv)++; (*argc)--;
		//fprintf(stderr, "got arg '%s' argc(%d)\n", arg, *argc);
		tag->strs[i] = arg;
		tag->num_elems++;
	}

	return 1;
}

static int parse_args(int argc, const char *argv[], struct args *args, struct nostr_event *ev)
{
	const char *arg, *arg2;
	uint64_t n;
	int has_added_tags = 0;

	argv++; argc--;
	for (; argc; ) {
		arg = *argv++; argc--;

		if (!strcmp(arg, "--help")) {
			usage();
		}

		if (!argc) {
			fprintf(stderr, "expected argument: '%s'\n", arg);
			return 0;
		}

		if (!strcmp(arg, "--sec")) {
			args->sec = *argv++; argc--;
		} else if (!strcmp(arg, "--created-at")) {
			arg = *argv++; argc--;
			if (!parse_num(arg, &args->created_at)) {
				fprintf(stderr, "created-at must be a unix timestamp\n");
				return 0;
			} else {
				args->flags |= HAS_CREATED_AT;
			}
		} else if (!strcmp(arg, "--kind")) {
			arg = *argv++; argc--;
			if (!parse_num(arg, &n)) {
				fprintf(stderr, "kind should be a number, got '%s'\n", arg);
				return 0;
			}
			args->kind = (int)n;
			args->flags |= HAS_KIND;
		} else if (!strcmp(arg, "--envelope")) {
			args->flags |= HAS_ENVELOPE;
		} else if (!strcmp(arg, "--tags")) {
			if (args->flags & HAS_DIFFICULTY) {
				fprintf(stderr, "can't combine --tags and --pow (yet)\n");
				return 0;
			}
			if (has_added_tags) {
				fprintf(stderr, "can't combine --tags and --tag (yet)");
				return 0;
			}
			arg = *argv++; argc--;
			args->tags = arg;
		} else if (!strcmp(arg, "-e")) {
			has_added_tags = 1;
			arg = *argv++; argc--;
			if (!nostr_add_tag(ev, "e", arg)) {
				fprintf(stderr, "couldn't add e tag");
				return 0;
			}
		} else if (!strcmp(arg, "-p")) {
			has_added_tags = 1;
			arg = *argv++; argc--;
			if (!nostr_add_tag(ev, "p", arg)) {
				fprintf(stderr, "couldn't add p tag");
				return 0;
			}
		} else if (!strcmp(arg, "-t")) {
			has_added_tags = 1;
			arg = *argv++; argc--;
			if (!nostr_add_tag(ev, "t", arg)) {
				fprintf(stderr, "couldn't add t tag");
				return 0;
			}
		} else if (!strcmp(arg, "--tagn")) {
			if (!nostr_add_arg_tags(ev, &argc, &argv)) {
				return 0;
			}
			has_added_tags = 1;
		} else if (!strcmp(arg, "--tag")) {
			has_added_tags = 1;
			if (args->tags) {
				fprintf(stderr, "can't combine --tag and --tags (yet)");
				return 0;
			}
			arg = *argv++; argc--;
			if (argc == 0) {
				fprintf(stderr, "expected two arguments to --tag\n");
				return 0;
			}
			arg2 = *argv++; argc--;
			if (!nostr_add_tag(ev, arg, arg2)) {
				fprintf(stderr, "couldn't add tag '%s' '%s'\n", arg, arg2);
				return 0;
			}
		} else if (!strcmp(arg, "--mine-pubkey")) {
			args->flags |= HAS_MINE_PUBKEY;
		} else if (!strcmp(arg, "--pow")) {
			if (args->tags) {
				fprintf(stderr, "can't combine --tags and --pow (yet)\n");
				return 0;
			}
			arg = *argv++; argc--;
			if (!parse_num(arg, &n)) {
				fprintf(stderr, "could not parse difficulty as number: '%s'\n", arg);
				return 0;
			}
			args->difficulty = n;
			args->flags |= HAS_DIFFICULTY;
		} else if (!strcmp(arg, "--dm")) {
			arg = *argv++; argc--;
			if (!hex_decode(arg, strlen(arg), args->encrypt_to, 32)) {
				fprintf(stderr, "could not decode encrypt-to pubkey");
				return 0;
			}
			args->flags |= HAS_ENCRYPT;
		} else if (!strcmp(arg, "--content")) {
			arg = *argv++; argc--;
			args->content = arg;
		} else if (!strcmp(arg, "--giftwrap-to")) {
			arg = *argv++; argc--;
			if (!hex_decode(arg, strlen(arg), args->encrypt_to, 32)) {
				fprintf(stderr, "could not decode giftwrap-to pubkey");
				return 0;
			}
			args->flags |= HAS_GIFTWRAP;
		} else {
			fprintf(stderr, "unexpected argument '%s'\n", arg);
			return 0;
		}
	}

	if (!args->content)
		args->content = "";

	return 1;
}

static int aes_encrypt(unsigned char *key, unsigned char *iv,
		unsigned char *buf, size_t buflen)
{
	struct AES_ctx ctx;
	unsigned char padding;
	int i;
	struct cursor cur;

	padding = 16 - (buflen % 16);
	make_cursor(buf, buf + buflen + padding, &cur);
	cur.p += buflen;
	//fprintf(stderr, "aes_encrypt: len %ld, padding %d\n", buflen, padding);

	for (i = 0; i < padding; i++) {
		if (!cursor_push_byte(&cur, padding)) {
			return 0;
		}
	}
	assert(cur.p == cur.end);
	assert((cur.p - cur.start) % 16 == 0);

	AES_init_ctx_iv(&ctx, key, iv);
	//fprintf(stderr, "encrypting %ld bytes: ", cur.p - cur.start);
	//print_hex(cur.start, cur.p - cur.start);
	AES_CBC_encrypt_buffer(&ctx, cur.start, cur.p - cur.start);

	return cur.p - cur.start;
}

static int copyx(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
	memcpy(output, x32, 32);
	return 1;
}

static int ensure_nonce_tag(struct nostr_event *ev, int target, int *index)
{
	char *str_target = malloc(8);
	struct nostr_tag *tag;
	int i;

	for (i = 0; i < ev->num_tags; i++) {
		tag = &ev->tags[i];
		if (tag->num_elems == 2 && !strcmp(tag->strs[0], "nonce")) {
			*index = i;
			return 1;
		}
	}

	*index = ev->num_tags;

	snprintf(str_target, 7, "%d", target);
	const char *ts[] = { "nonce", "0", str_target };

	return nostr_add_tag_n(ev, ts, 3);
}

static int mine_event(struct nostr_event *ev, int difficulty,
		      unsigned char *buf, size_t bufsize)
{
	char *strnonce = malloc(33);
	struct nostr_tag *tag;
	uint64_t nonce;
	int index, res;

	if (!ensure_nonce_tag(ev, difficulty, &index))
		return 0;

	tag = &ev->tags[index];
	assert(tag->num_elems == 3);
	assert(!strcmp(tag->strs[0], "nonce"));
	tag->strs[1] = strnonce;

	for (nonce = 0;; nonce++) {
		snprintf(strnonce, 32, "%" PRIu64, nonce);

		if (!generate_event_id(ev, buf, bufsize))
			return 0;

		if ((res = count_leading_zero_bits(ev->id)) >= difficulty) {
			fprintf(stderr, "mined %d bits\n", res);
			return 1;
		}
	}

	return 0;
}

static int make_giftwrap(secp256k1_context *ctx, struct key *key,
		struct nostr_event *rumor, unsigned char receiver_pubkey[32],
		unsigned char *buf, size_t bufsize,
		int is_envelope)
{
	struct nostr_event giftwrap = {0};
	struct nostr_event seal = {0};
	struct key wrap_key;
	char *b64, *json;
	struct cursor arena, *c;
	ssize_t b64_len;
	enum ndb_decrypt_result ok;

	c = &arena;
	make_cursor(buf, buf+bufsize, c);
	if (!fill_random(wrap_key.secret, sizeof(wrap_key.secret)))
		return 0;
	create_key(ctx, &wrap_key); /* giftwrap key */

	memcpy(rumor->pubkey, key->pubkey, 32);
	if (!generate_event_id(rumor, c->p, cursor_remaining_capacity(c)))
		return 0;

	/* rumor data */
	json = (char*)c->p;
	if (!event_to_json(c, rumor, 0))
		return 0;

	ok = nip44_encrypt(ctx, key->secret, receiver_pubkey,
			   (unsigned char *)json, c->p - (unsigned char *)json-1,
			   c->p, cursor_remaining_capacity(c),
			   &b64, &b64_len);

	if (ok != NIP44_OK) {
		fprintf(stderr, "rumor nip44 encrypt failed: %s\n",
				nip44_err_msg(ok));
		return 0;
	}
	assert(b64_len % 4 == 0);
	c->p = b64 + b64_len;
	if (!cursor_push_byte(c, 0))
		return 0;

	fprintf(stderr, "rumor %s\n\n", json);

	/* seal data */
	seal.kind = 13;
	seal.created_at = rumor->created_at;
	seal.content = b64;
	assert(strlen(b64) % 4 == 0);

	memcpy(seal.pubkey, key->pubkey, 32);
	if (!generate_event_id(&seal, c->p, cursor_remaining_capacity(c)))
		return 0;
	if (!sign_event(ctx, key, &seal))
		return 0;

	json = (char*)c->p;
	if (!event_to_json(c, &seal, 0)) {
		fprintf(stderr, "seal -> json failed, not enough space?\n");
		return 0;
	}
	fprintf(stderr, "seal %.*s\n\n", (int)(c->p - (unsigned char*)json), json);

	/* encrypt seal for giftwrap contents */
	ok = nip44_encrypt(ctx, wrap_key.secret, receiver_pubkey,
			  (unsigned char *)json, c->p - (unsigned char *)json - 1,
			  c->p, cursor_remaining_capacity(c),
			  &b64, &b64_len);

	if (ok != NIP44_OK) {
		fprintf(stderr, "seal nip44 encrypt failed: %s\n",
				nip44_err_msg(ok));
		return 0;
	}

	assert(b64_len % 4 == 0);
	c->p = b64 + b64_len;
	if (!cursor_push_byte(c, 0))
		return 0;

	giftwrap.content = b64;

	/* giftwrap data */
	json = (char*)c->p;
	if (!cursor_push_hex(c, wrap_key.secret, 32)) {
		fprintf(stderr, "buffer too small, bug jb55 to increase\n");
		return 0;
	}
	fprintf(stderr, "giftwrap_sec %.*s\n\n", 64, json);

	giftwrap.created_at = rumor->created_at;
	giftwrap.kind = 1059;
	memcpy(giftwrap.pubkey, wrap_key.pubkey, 32);

	json = (char*)c->p;
	cursor_push_hex(c, receiver_pubkey, 32);
	cursor_push_byte(c, 0);
	nostr_add_tag(&giftwrap, "p", json);

	if (!generate_event_id(&giftwrap, c->p, cursor_remaining_capacity(c)))
		return 0;
	if (!sign_event(ctx, &wrap_key, &giftwrap))
		return 0;

	json = (char*)c->p;
	if (!event_to_json(c, &giftwrap, is_envelope)) {
		fprintf(stderr, "buffer too small, bug jb55 to increase\n");
		return 0;
	}

	printf("%s\n", json);

	free(buf);
	return 1;
}

static int make_encrypted_dm(secp256k1_context *ctx, struct key *key,
		struct nostr_event *ev, unsigned char nostr_pubkey[32], int kind)
{
	size_t inl = strlen(ev->content);
	int enclen = inl + 16;
	size_t buflen = enclen * 3 + 65 * 10;
	unsigned char *buf = malloc(buflen);
	unsigned char shared_secret[32];
	unsigned char iv[16];
	unsigned char compressed_pubkey[33];
	int content_len = strlen(ev->content);
	unsigned char encbuf[content_len + (content_len % 16) + 1];
	struct cursor cur;
	secp256k1_pubkey pubkey;

	compressed_pubkey[0] = 2;
	memcpy(&compressed_pubkey[1], nostr_pubkey, 32);

	make_cursor(buf, buf + buflen, &cur);

        if (!secp256k1_ec_seckey_verify(ctx, key->secret)) {
		fprintf(stderr, "make_encrypted_dm: ec_seckey_verify failed\n");
		return 0;
	}

	if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_pubkey,
				       sizeof(compressed_pubkey))) {
		fprintf(stderr, "make_encrypted_dm: ec_pubkey_parse failed\n");
		return 0;
	}

	if (!secp256k1_ecdh(ctx, shared_secret, &pubkey, key->secret, copyx, NULL)) {
		fprintf(stderr, "make_encrypted_dm: secp256k1_ecdh failed\n");
		return 0;
	}

	if (!fill_random(iv, sizeof(iv))) {
		fprintf(stderr, "make_encrypted_dm: fill_random failed\n");
		return 0;
	}

	fprintf(stderr, "shared_secret ");
	print_hex(shared_secret, 32);

	memcpy(encbuf, ev->content, strlen(ev->content));
	enclen = aes_encrypt(shared_secret, iv, encbuf, strlen(ev->content));
	if (enclen == 0) {
		fprintf(stderr, "make_encrypted_dm: aes_encrypt failed\n");
		free(buf);
		return 0;
	}

	if ((enclen = base64_encode((char *)buf, buflen, (const char*)encbuf, enclen)) == -1) {
		fprintf(stderr, "make_encrypted_dm: base64 encode of encrypted fata failed\n");
		return 0;
	}
	cur.p += enclen;

	if (!cursor_push_str(&cur, "?iv=")) {
		fprintf(stderr, "make_encrypted_dm: buffer too small\n");
		return 0;
	}

	if ((enclen = base64_encode((char *)cur.p, cur.end - cur.p, (const char*)iv, 16)) == -1) {
		fprintf(stderr, "make_encrypted_dm: base64 encode of iv failed\n");
		return 0;
	}
	cur.p += enclen;

	if (!cursor_push_byte(&cur, 0)) {
		fprintf(stderr, "make_encrypted_dm: out of memory by 1 byte!\n");
		return 0;
	}

	ev->content = (const char*)cur.start;
	ev->kind = kind;

	if (!hex_encode(nostr_pubkey, 32, (char*)cur.p, cur.end - cur.p))
		return 0;

	if (!nostr_add_tag(ev, "p", (const char*)cur.p)) {
		fprintf(stderr, "too many tags\n");
		return 0;
	}

	cur.p += 65;

	return 1;
}

static void try_subcommand(int argc, const char *argv[])
{
	static char buf[128] = {0};
	const char *sub = argv[1];
	if (strlen(sub) >= 1 && sub[0] != '-') {
		snprintf(buf, sizeof(buf)-1, "nostril-%s", sub);
		execvp(buf, (char * const *)argv+1);
	}
}


int main(int argc, const char *argv[])
{
	struct args args = {0};
	struct nostr_event ev = {0};
	struct key key;
	unsigned char *buf;
	size_t bufsize;
        secp256k1_context *ctx;

	if (argc < 2)
		usage();

        if (!init_secp_context(&ctx))
		return 2;

	try_subcommand(argc, argv);

	if (!parse_args(argc, argv, &args, &ev)) {
		usage();
		return 10;
	}

	if (args.tags) {
		ev.explicit_tags = args.tags;
	}

	make_event_from_args(&ev, &args);

	if (args.sec) {
		if (!decode_key(ctx, args.sec, &key)) {
			return 8;
		}
	} else {
		int *difficulty = NULL;
		if ((args.flags & HAS_DIFFICULTY) && (args.flags & HAS_MINE_PUBKEY)) {
			difficulty = &args.difficulty;
		}

		if (!generate_key(ctx, &key, difficulty)) {
			fprintf(stderr, "could not generate key\n");
			return 4;
		}
		fprintf(stderr, "secret_key ");
		print_hex(key.secret, sizeof(key.secret));
		fprintf(stderr, "\n");
	}

	/* 8 MiB */
	bufsize = 2 << 22;
	buf = malloc(bufsize);

	if (args.flags & HAS_ENCRYPT) {
		int kind = args.flags & HAS_KIND? args.kind : 4;
		if (!make_encrypted_dm(ctx, &key, &ev, args.encrypt_to, kind)) {
			fprintf(stderr, "error making encrypted dm\n");
			return 1;
		}
	} else if (args.flags & HAS_GIFTWRAP) {
		if (!make_giftwrap(ctx, &key, &ev, args.encrypt_to,
				   buf, bufsize, args.flags & HAS_ENVELOPE)) {
			fprintf(stderr, "error making encrypted dm\n");
			return 1;
		}
		return 0;
	}

	// set the event's pubkey
	memcpy(ev.pubkey, key.pubkey, 32);

	if (args.flags & HAS_DIFFICULTY && !(args.flags & HAS_MINE_PUBKEY)) {
		if (!mine_event(&ev, args.difficulty, buf, bufsize)) {
			fprintf(stderr, "error when mining id\n");
			return 22;
		}
	} else {
		if (!generate_event_id(&ev, buf, bufsize)) {
			fprintf(stderr, "could not generate event id\n");
			return 5;
		}
	}

	if (!sign_event(ctx, &key, &ev)) {
		fprintf(stderr, "could not sign event\n");
		return 6;
	}

	if (!print_event(&ev, args.flags & HAS_ENVELOPE, buf, bufsize)) {
		fprintf(stderr, "buffer too small\n");
		return 88;
	}

	free(buf);

	return 0;
}

