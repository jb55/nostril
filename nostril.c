
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include "cursor.h"
#include "hex.h"
#include "sha256.h"
#include "random.h"

#define MAX_TAGS 32
#define MAX_TAG_ELEMS 16

#define HAS_CREATED_AT (1<<1)
#define HAS_KIND (1<<2)
#define HAS_ENVELOPE (1<<2)

struct key {
	secp256k1_keypair pair;
	unsigned char pubkey[32];
};

struct args {
	unsigned int flags;
	int kind;

	const char *sec;
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

	struct nostr_tag tags[MAX_TAGS];
	int num_tags;
};

void usage()
{
	printf("usage: nostril <content>\n");
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

	return secp256k1_schnorrsig_sign(ctx, sig, id, &key->pair, aux);
}

static int create_key(secp256k1_context *ctx, struct key *key, unsigned char seckey[32])
{
	secp256k1_xonly_pubkey pubkey;

	/* Try to create a keypair with a valid context, it should only
	 * fail if the secret key is zero or out of range. */
	if (!secp256k1_keypair_create(ctx, &key->pair, seckey))
		return 0;

	if (!secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &key->pair))
		return 0;

	/* Serialize the public key. Should always return 1 for a valid public key. */
	return secp256k1_xonly_pubkey_serialize(ctx, key->pubkey, &pubkey);
}

static int decode_key(secp256k1_context *ctx, const char *secstr, struct key *key)
{
	unsigned char seckey[32];
	int ok;

	if (!hex_decode(secstr, strlen(secstr), seckey, 32)) {
		fprintf(stderr, "could not hex decode secret key\n");
		return 0;
	}

	return create_key(ctx, key, seckey);
}

static int generate_key(secp256k1_context *ctx, struct key *key)
{
	unsigned char seckey[32];

	/* If the secret key is zero or out of range (bigger than secp256k1's
	 * order), we try to sample a new key. Note that the probability of this
	 * happening is negligible. */
	if (!fill_random(seckey, sizeof(seckey))) {
		return 0;
	}

	return create_key(ctx, key, seckey);
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

static int generate_event_id(struct nostr_event *ev)
{
	static unsigned char buf[32000];

	int len;

	if (!(len = event_commitment(ev, buf, sizeof(buf)))) {
		fprintf(stderr, "event_commitment: buffer out of space\n");
		return 0;
	}

	//fprintf(stderr, "commitment: '%.*s'\n", len, buf);
	
	sha256((struct sha256*)ev->id, buf, len);

	return 1;
}

static int sign_event(secp256k1_context *ctx, struct key *key, struct nostr_event *ev)
{
	if (!make_sig(ctx, key, ev->id, ev->sig)) {
		fprintf(stderr, "Signature generation failed\n");
		return 0;
	}

	return 1;
}

static int print_event(struct nostr_event *ev, int envelope)
{
	unsigned char buf[32000];
	char pubkey[65];
	char id[65];
	char sig[129];
	struct cursor cur;
	int ok;

	ok = hex_encode(ev->id, sizeof(ev->id), id, sizeof(id)) &&
	hex_encode(ev->pubkey, sizeof(ev->pubkey), pubkey, sizeof(pubkey)) &&
	hex_encode(ev->sig, sizeof(ev->sig), sig, sizeof(sig));

	assert(ok);

	make_cursor(buf, buf+sizeof(buf), &cur);
	if (!cursor_push_tags(&cur, ev))
		return 0;

	if (envelope)
		printf("[\"EVENT\",");

	printf("{\"id\": \"%s\",", id);
	printf("\"pubkey\": \"%s\",", pubkey);
	printf("\"created_at\": %" PRIu64 ",", ev->created_at);
	printf("\"kind\": %d,", ev->kind);
	printf("\"tags\": %.*s,", (int)cursor_len(&cur), cur.start);

	reset_cursor(&cur);
	if (!cursor_push_jsonstr(&cur, ev->content))
		return 0;

	printf("\"content\": %.*s,", (int)cursor_len(&cur), cur.start);
	printf("\"sig\": \"%s\"}", sig);

	if (envelope)
		printf("]");

	printf("\n");
	
	return 1;
}

static void make_event_from_args(struct nostr_event *ev, struct args *args)
{
	ev->tags[0].strs[0] = "tag";
	ev->tags[0].strs[1] = "a";
	ev->tags[0].num_elems = 2;
	ev->num_tags = 0;

	ev->created_at = args->flags & HAS_CREATED_AT? args->created_at : time(NULL);
	ev->content = args->content;
	ev->kind = 1;
}

static int parse_num(const char *arg, uint64_t *t)
{
	*t = strtol(arg, NULL, 10); 
	return errno != EINVAL;
}

static int parse_args(int argc, const char *argv[], struct args *args)
{
	const char *arg;
	uint64_t n;

	argv++; argc--;
	for (; argc; ) {
		arg = *argv++; argc--;
		if (!argc) {
			args->content = arg;
			return 1;
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
			if (!parse_num(arg, &n)) {
				fprintf(stderr, "kind should be a number, got '%s'\n", arg);
				return 0;
			}
			args->kind = (int)n;
			args->flags |= HAS_KIND;
		} else if (!strcmp(arg, "--envelope")) {
			args->flags |= HAS_ENVELOPE;
		} else if (!strncmp(arg, "--", 2)) {
			fprintf(stderr, "unknown argument: %s\n", arg);
			return 0;
		}
	}

	return 1;
}

int main(int argc, const char *argv[])
{
	struct args args = {0};
	struct nostr_event ev = {0};
	struct key key;
        secp256k1_context *ctx;
	int ok;

	if (argc < 2)
		usage();

        if (!init_secp_context(&ctx))
		return 2;

	if (!parse_args(argc, argv, &args))
		return 10;

	make_event_from_args(&ev, &args);

	if (args.sec) {
		if (!decode_key(ctx, args.sec, &key)) {
			return 8;
		}
	} else {
		if (!generate_key(ctx, &key)) {
			fprintf(stderr, "could not generate key");
			return 4;
		}
	}

	// set the event's pubkey
	memcpy(ev.pubkey, key.pubkey, 32);

	if (!generate_event_id(&ev)) {
		fprintf(stderr, "could not generate event id\n");
		return 5;
	}

	if (!sign_event(ctx, &key, &ev)) {
		fprintf(stderr, "could not sign event\n");
		return 6;
	}

	if (!print_event(&ev, args.flags & HAS_ENVELOPE)) {
		fprintf(stderr, "buffer too small\n");
		return 88;
	}

	return 0;
}

