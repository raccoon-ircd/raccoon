/*
 * Charybdis: an advanced ircd
 * ip_cloaking_5nolssl.c: provide user hostname cloaking
 *
 * Written originally by nenolod, altered to use FNV by Elizabeth in 2008
 * altered some more by groente
 *
 * Further modified, after initial modification by ellenor to use sha256-hmac,
 * to use bundled sha256 and thus not depend on openssl/libressl (hence
 * "nolssl")
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "newconf.h"

/* SHA256-based Unix crypt implementation.
   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */

/* Structure to save state of computation between the single steps.  */
struct sha256_ctx
{
	uint32_t H[8];

	uint32_t total[2];
	uint32_t buflen;
	char buffer[128];	/* NB: always correctly aligned for uint32_t.  */
};

#ifndef WORDS_BIGENDIAN
#	define SHA256_SWAP(n) \
		(((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#else
#	define SHA256_SWAP(n) (n)
#endif

/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (FIPS 180-2:5.1.1)  */
static const unsigned char SHA256_fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */  };


/* Constants for SHA256 from FIPS 180-2:4.2.2.  */
static const uint32_t SHA256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
static void sha256_process_block(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
	const uint32_t *words = buffer;
	size_t nwords = len / sizeof(uint32_t);
	uint32_t a = ctx->H[0];
	uint32_t b = ctx->H[1];
	uint32_t c = ctx->H[2];
	uint32_t d = ctx->H[3];
	uint32_t e = ctx->H[4];
	uint32_t f = ctx->H[5];
	uint32_t g = ctx->H[6];
	uint32_t h = ctx->H[7];

	/* First increment the byte count.  FIPS 180-2 specifies the possible
	   length of the file up to 2^64 bits.  Here we only compute the
	   number of bytes.  Do a double word increment.  */
	ctx->total[0] += len;
	if (ctx->total[0] < len)
		++ctx->total[1];

	/* Process all bytes in the buffer with 64 bytes in each round of
	   the loop.  */
	while (nwords > 0)
	{
		uint32_t W[64];
		uint32_t a_save = a;
		uint32_t b_save = b;
		uint32_t c_save = c;
		uint32_t d_save = d;
		uint32_t e_save = e;
		uint32_t f_save = f;
		uint32_t g_save = g;
		uint32_t h_save = h;
		unsigned int t;

		/* Operators defined in FIPS 180-2:4.1.2.  */
		#define SHA256_Ch(x, y, z) ((x & y) ^ (~x & z))
		#define SHA256_Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
		#define SHA256_S0(x) (SHA256_CYCLIC (x, 2) ^ SHA256_CYCLIC (x, 13) ^ SHA256_CYCLIC (x, 22))
		#define SHA256_S1(x) (SHA256_CYCLIC (x, 6) ^ SHA256_CYCLIC (x, 11) ^ SHA256_CYCLIC (x, 25))
		#define SHA256_R0(x) (SHA256_CYCLIC (x, 7) ^ SHA256_CYCLIC (x, 18) ^ (x >> 3))
		#define SHA256_R1(x) (SHA256_CYCLIC (x, 17) ^ SHA256_CYCLIC (x, 19) ^ (x >> 10))

		/* It is unfortunate that C does not provide an operator for
		   cyclic rotation.  Hope the C compiler is smart enough.  */
		#define SHA256_CYCLIC(w, s) ((w >> s) | (w << (32 - s)))

		/* Compute the message schedule according to FIPS 180-2:6.2.2 step 2.  */
		for (t = 0; t < 16; ++t)
		{
			W[t] = SHA256_SWAP(*words);
			++words;
		}
		for (t = 16; t < 64; ++t)
			W[t] = SHA256_R1(W[t - 2]) + W[t - 7] + SHA256_R0(W[t - 15]) + W[t - 16];

		/* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
		for (t = 0; t < 64; ++t)
		{
			uint32_t T1 = h + SHA256_S1(e) + SHA256_Ch(e, f, g) + SHA256_K[t] + W[t];
			uint32_t T2 = SHA256_S0(a) + SHA256_Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		/* Add the starting values of the context according to FIPS 180-2:6.2.2
		   step 4.  */
		a += a_save;
		b += b_save;
		c += c_save;
		d += d_save;
		e += e_save;
		f += f_save;
		g += g_save;
		h += h_save;

		/* Prepare for the next round.  */
		nwords -= 16;
	}

	/* Put checksum in context given as argument.  */
	ctx->H[0] = a;
	ctx->H[1] = b;
	ctx->H[2] = c;
	ctx->H[3] = d;
	ctx->H[4] = e;
	ctx->H[5] = f;
	ctx->H[6] = g;
	ctx->H[7] = h;
}


/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2)  */
static void sha256_init_ctx(struct sha256_ctx *ctx)
{
	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;

	ctx->total[0] = ctx->total[1] = 0;
	ctx->buflen = 0;
}


/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
static void *sha256_finish_ctx(struct sha256_ctx *ctx, void *resbuf)
{
	/* Take yet unprocessed bytes into account.  */
	uint32_t bytes = ctx->buflen;
	size_t pad;
	unsigned int i;

	/* Now count remaining bytes.  */
	ctx->total[0] += bytes;
	if (ctx->total[0] < bytes)
		++ctx->total[1];

	pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
	memcpy(&ctx->buffer[bytes], SHA256_fillbuf, pad);

	/* Put the 64-bit file length in *bits* at the end of the buffer.  */
	*(uint32_t *) & ctx->buffer[bytes + pad + 4] = SHA256_SWAP(ctx->total[0] << 3);
	*(uint32_t *) & ctx->buffer[bytes + pad] = SHA256_SWAP((ctx->total[1] << 3) |
							(ctx->total[0] >> 29));

	/* Process last bytes.  */
	sha256_process_block(ctx->buffer, bytes + pad + 8, ctx);

	/* Put result from CTX in first 32 bytes following RESBUF.  */
	for (i = 0; i < 8; ++i)
		((uint32_t *) resbuf)[i] = SHA256_SWAP(ctx->H[i]);

	return resbuf;
}


static void sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
	/* When we already have some bits in our internal buffer concatenate
	   both inputs first.  */
	if (ctx->buflen != 0)
	{
		size_t left_over = ctx->buflen;
		size_t add = 128 - left_over > len ? len : 128 - left_over;

		memcpy(&ctx->buffer[left_over], buffer, add);
		ctx->buflen += add;

		if (ctx->buflen > 64)
		{
			sha256_process_block(ctx->buffer, ctx->buflen & ~63, ctx);

			ctx->buflen &= 63;
			/* The regions in the following copy operation cannot overlap.  */
			memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~63], ctx->buflen);
		}

		buffer = (const char *)buffer + add;
		len -= add;
	}

	/* Process available complete blocks.  */
	if (len >= 64)
	{
		/* To check alignment gcc has an appropriate operator.  Other
		   compilers don't.  */
		#if __GNUC__ >= 2
		#	define SHA256_UNALIGNED_P(p) (((uintptr_t) p) % __alignof__ (uint32_t) != 0)
		#else
		#	define SHA256_UNALIGNED_P(p) (((uintptr_t) p) % sizeof (uint32_t) != 0)
		#endif
		if (SHA256_UNALIGNED_P(buffer))
			while (len > 64)
			{
				sha256_process_block(memcpy(ctx->buffer, buffer, 64), 64, ctx);
				buffer = (const char *)buffer + 64;
				len -= 64;
			}
		else
		{
			sha256_process_block(buffer, len & ~63, ctx);
			buffer = (const char *)buffer + (len & ~63);
			len &= 63;
		}
	}

	/* Move remaining bytes into internal buffer.  */
	if (len > 0)
	{
		size_t left_over = ctx->buflen;

		memcpy(&ctx->buffer[left_over], buffer, len);
		left_over += len;
		if (left_over >= 64)
		{
			sha256_process_block(ctx->buffer, 64, ctx);
			left_over -= 64;
			memcpy(ctx->buffer, &ctx->buffer[64], left_over);
		}
		ctx->buflen = left_over;
	}
}


/* Define our magic string to mark salt for SHA256 "encryption"
   replacement.  */
static const char sha256_salt_prefix[] = "$5$";

/* Prefix for optional rounds specification.  */
static const char sha256_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SHA256_SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define SHA256_ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define SHA256_ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define SHA256_ROUNDS_MAX 999999999

static void sha256_hash(const char *inbuf, char *outbuf, int buflen) {
	// rounds 64 (1 round in crypt parlance)
	unsigned char temp_result[32] __attribute__ ((__aligned__(__alignof__(uint32_t))));
	struct sha256_ctx ctx;
	size_t in_len;
	size_t cnt;
	char *cp;
	char *copied_key = NULL;
	char *copied_salt = NULL;
	char *p_bytes;
	char *s_bytes;
	sha256_init_ctx(&ctx);
	sha256_process_bytes(inbuf, strlen(inbuf), &ctx);
	sha256_finish_ctx(&ctx, temp_result);

	memcpy(outbuf, temp_result, buflen);
}

static char *sha256_crypt_r(const char *key, const char *salt, char *buffer, int buflen)
{
	unsigned char alt_result[32] __attribute__ ((__aligned__(__alignof__(uint32_t))));
	unsigned char temp_result[32] __attribute__ ((__aligned__(__alignof__(uint32_t))));
	struct sha256_ctx ctx;
	struct sha256_ctx alt_ctx;
	size_t salt_len;
	size_t key_len;
	size_t cnt;
	char *cp;
	char *copied_key = NULL;
	char *copied_salt = NULL;
	char *p_bytes;
	char *s_bytes;
	/* Default number of rounds.  */
	size_t rounds = SHA256_ROUNDS_DEFAULT;
	int rounds_custom = 0;

	/* Find beginning of salt string.  The prefix should normally always
	   be present.  Just in case it is not.  */
	if (strncmp(sha256_salt_prefix, salt, sizeof(sha256_salt_prefix) - 1) == 0)
		/* Skip salt prefix.  */
		salt += sizeof(sha256_salt_prefix) - 1;

	if (strncmp(salt, sha256_rounds_prefix, sizeof(sha256_rounds_prefix) - 1) == 0)
	{
		const char *num = salt + sizeof(sha256_rounds_prefix) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			salt = endp + 1;
			rounds = MAX(SHA256_ROUNDS_MIN, MIN(srounds, SHA256_ROUNDS_MAX));
			rounds_custom = 1;
		}
	}

	salt_len = MIN(strcspn(salt, "$"), SHA256_SALT_LEN_MAX);
	key_len = strlen(key);

	if ((key - (char *)0) % __alignof__(uint32_t) != 0)
	{
		char *tmp = (char *)alloca(key_len + __alignof__(uint32_t));
		key = copied_key =
			memcpy(tmp + __alignof__(uint32_t)
			       - (tmp - (char *)0) % __alignof__(uint32_t), key, key_len);
	}

	if ((salt - (char *)0) % __alignof__(uint32_t) != 0)
	{
		char *tmp = (char *)alloca(salt_len + __alignof__(uint32_t));
		salt = copied_salt =
			memcpy(tmp + __alignof__(uint32_t)
			       - (tmp - (char *)0) % __alignof__(uint32_t), salt, salt_len);
	}

	/* Prepare for the real work.  */
	sha256_init_ctx(&ctx);

	/* Add the key string.  */
	sha256_process_bytes(key, key_len, &ctx);

	/* The last part is the salt string.  This must be at most 16
	   characters and it ends at the first `$' character (for
	   compatibility with existing implementations).  */
	sha256_process_bytes(salt, salt_len, &ctx);


	/* Compute alternate SHA256 sum with input KEY, SALT, and KEY.  The
	   final result will be added to the first context.  */
	sha256_init_ctx(&alt_ctx);

	/* Add key.  */
	sha256_process_bytes(key, key_len, &alt_ctx);

	/* Add salt.  */
	sha256_process_bytes(salt, salt_len, &alt_ctx);

	/* Add key again.  */
	sha256_process_bytes(key, key_len, &alt_ctx);

	/* Now get result of this (32 bytes) and add it to the other
	   context.  */
	sha256_finish_ctx(&alt_ctx, alt_result);

	/* Add for any character in the key one byte of the alternate sum.  */
	for (cnt = key_len; cnt > 32; cnt -= 32)
		sha256_process_bytes(alt_result, 32, &ctx);
	sha256_process_bytes(alt_result, cnt, &ctx);

	/* Take the binary representation of the length of the key and for every
	   1 add the alternate sum, for every 0 the key.  */
	for (cnt = key_len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			sha256_process_bytes(alt_result, 32, &ctx);
		else
			sha256_process_bytes(key, key_len, &ctx);

	/* Create intermediate result.  */
	sha256_finish_ctx(&ctx, alt_result);

	/* Start computation of P byte sequence.  */
	sha256_init_ctx(&alt_ctx);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < key_len; ++cnt)
		sha256_process_bytes(key, key_len, &alt_ctx);

	/* Finish the digest.  */
	sha256_finish_ctx(&alt_ctx, temp_result);

	/* Create byte sequence P.  */
	cp = p_bytes = alloca(key_len);
	for (cnt = key_len; cnt >= 32; cnt -= 32)
	{
		memcpy(cp, temp_result, 32);
		cp += 32;
	}
	memcpy(cp, temp_result, cnt);

	/* Start computation of S byte sequence.  */
	sha256_init_ctx(&alt_ctx);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < (size_t)(16 + alt_result[0]); ++cnt)
		sha256_process_bytes(salt, salt_len, &alt_ctx);

	/* Finish the digest.  */
	sha256_finish_ctx(&alt_ctx, temp_result);

	/* Create byte sequence S.  */
	cp = s_bytes = alloca(salt_len);
	for (cnt = salt_len; cnt >= 32; cnt -= 32)
	{
		memcpy(cp, temp_result, 32);
		cp += 32;
	}
	memcpy(cp, temp_result, cnt);

	/* Repeatedly run the collected hash value through SHA256 to burn
	   CPU cycles.  */
	for (cnt = 0; cnt < rounds; ++cnt)
	{
		/* New context.  */
		sha256_init_ctx(&ctx);

		/* Add key or last result.  */
		if ((cnt & 1) != 0)
			sha256_process_bytes(p_bytes, key_len, &ctx);
		else
			sha256_process_bytes(alt_result, 32, &ctx);

		/* Add salt for numbers not divisible by 3.  */
		if (cnt % 3 != 0)
			sha256_process_bytes(s_bytes, salt_len, &ctx);

		/* Add key for numbers not divisible by 7.  */
		if (cnt % 7 != 0)
			sha256_process_bytes(p_bytes, key_len, &ctx);

		/* Add key or last result.  */
		if ((cnt & 1) != 0)
			sha256_process_bytes(alt_result, 32, &ctx);
		else
			sha256_process_bytes(p_bytes, key_len, &ctx);

		/* Create intermediate result.  */
		sha256_finish_ctx(&ctx, alt_result);
	}

	/* Now we can construct the result string.  It consists of three
	   parts.  */
	memset(buffer, '\0', MAX(0, buflen));
	strncpy(buffer, sha256_salt_prefix, MAX(0, buflen));
	if((cp = strchr(buffer, '\0')) == NULL)
		cp = buffer + MAX(0, buflen);
	buflen -= sizeof(sha256_salt_prefix) - 1;

	if (rounds_custom)
	{
		int n = snprintf(cp, MAX(0, buflen), "%s%zu$",
				 sha256_rounds_prefix, rounds);
		cp += n;
		buflen -= n;
	}

	memset(cp, '\0', salt_len);
	strncpy(cp, salt, MIN((size_t) MAX(0, buflen), salt_len));
	if((cp = strchr(buffer, '\0')) == NULL)
		cp += salt_len;
	buflen -= MIN((size_t) MAX(0, buflen), salt_len);

	if (buflen > 0)
	{
		*cp++ = '$';
		--buflen;
	}

	b64_from_24bit(alt_result[0], alt_result[10], alt_result[20], 4);
	b64_from_24bit(alt_result[21], alt_result[1], alt_result[11], 4);
	b64_from_24bit(alt_result[12], alt_result[22], alt_result[2], 4);
	b64_from_24bit(alt_result[3], alt_result[13], alt_result[23], 4);
	b64_from_24bit(alt_result[24], alt_result[4], alt_result[14], 4);
	b64_from_24bit(alt_result[15], alt_result[25], alt_result[5], 4);
	b64_from_24bit(alt_result[6], alt_result[16], alt_result[26], 4);
	b64_from_24bit(alt_result[27], alt_result[7], alt_result[17], 4);
	b64_from_24bit(alt_result[18], alt_result[28], alt_result[8], 4);
	b64_from_24bit(alt_result[9], alt_result[19], alt_result[29], 4);
	b64_from_24bit(0, alt_result[31], alt_result[30], 3);
	if (buflen <= 0)
	{
		errno = ERANGE;
		buffer = NULL;
	}
	else
		*cp = '\0';	/* Terminate the string.  */

	/* Clear the buffer for the intermediate result so that people
	   attaching to processes or reading core dumps cannot get any
	   information.  We do it in this way to clear correct_words[]
	   inside the SHA256 implementation as well.  */
	sha256_init_ctx(&ctx);
	sha256_finish_ctx(&ctx, alt_result);
	memset(temp_result, '\0', sizeof(temp_result));
	memset(p_bytes, '\0', key_len);
	memset(s_bytes, '\0', salt_len);
	memset(&ctx, '\0', sizeof(ctx));
	memset(&alt_ctx, '\0', sizeof(alt_ctx));
	if (copied_key != NULL)
		memset(copied_key, '\0', key_len);
	if (copied_salt != NULL)
		memset(copied_salt, '\0', salt_len);

	return buffer;
}

char *secretsalt = "32qwnqoWI@DpMd&w";
char *cloakprefix = "net/";

static void
conf_set_secretsalt(void *data)
{
    secretsalt = rb_strdup(data);
}

static void
conf_set_cloakprefix(void *data)
{
    cloakprefix = rb_strdup(data);
}

static int
_modinit(void)
{
    /* add the usermode to the available slot */
    user_modes['x'] = find_umode_slot();
    user_mode_names['x'] = "cloaked";
    construct_umodebuf();

    add_top_conf("cloaking", NULL, NULL, NULL);
    add_conf_item("cloaking", "secretsalt", CF_QSTRING, conf_set_secretsalt);
    add_conf_item("cloaking", "prefix", CF_QSTRING, conf_set_cloakprefix);

    return 0;
}

static void
_moddeinit(void)
{
    /* disable the umode and remove it from the available list */
    user_modes['x'] = 0;
    user_mode_names['x'] = NULL;
    construct_umodebuf();

    remove_top_conf("cloaking");
    remove_conf_item("cloaking", "secretsalt");
    remove_conf_item("cloaking", "prefix");
}

static void check_umode_change(void *data);
static void check_new_user(void *data);
mapi_hfn_list_av1 ip_cloaking_hfnlist[] = {
    { "umode_changed", (hookfn) check_umode_change },
    { "new_local_user", (hookfn) check_new_user },
    { NULL, NULL }
};

DECLARE_MODULE_AV1(ip_cloaking, _modinit, _moddeinit, NULL, NULL,
                   ip_cloaking_hfnlist, "$Revision: 3526 $");

static char *
do_cloak_part(const char *part)
{
    unsigned char hash[33] = "";
    char *inbuf = rb_strdup(part);
    char buf[129] = "";
    int i;
    for (i = strlen(part)+1;i>0;i--) {
        inbuf[i-1] = part[i-1] ^ secretsalt[(i-1)%strlen(secretsalt)];
    }
    // part on secretsalt
    sha256_hash(part, hash, 32);
    rb_snprintf(buf, sizeof(buf), "%.128X", hash);
    sendto_realops_snomask(SNO_GENERAL, L_ALL, "hash for part %s is %.128X", part, hash);
    return rb_strdup(buf);
}

static char *
do_ip_cloak_part(const char *part)
{
    char buf[33] = "";
    char *hash = do_cloak_part(part);
    rb_snprintf(buf, sizeof(buf), "%c%c%c%c%c%c%c%c", *hash, *(hash+1), *(hash+2), *(hash+3), *(hash+4), *(hash+5), *(hash+6), *(hash+7));
    return rb_strdup(buf);
}

static void
do_ip_cloak(const char *inbuf, char *outbuf)
{
    unsigned int a, b, c, d;
    struct in_addr in_addr;
    char buf[512], *alpha, *beta, *gamma;
    alpha = rb_malloc(512);
    beta = rb_malloc(512);
    gamma = rb_malloc(512);
    rb_inet_pton(AF_INET, inbuf, &in_addr);
    a = (in_addr.s_addr & 0xff000000) >> 24;
    b = (in_addr.s_addr & 0x00ff0000) >> 16;
    c = (in_addr.s_addr & 0x0000ff00) >> 8;
    d = in_addr.s_addr & 0x000000ff;
    rb_sprintf(alpha, "%s", inbuf);
    rb_sprintf(beta, "%u.%u.%u", a, b, c);
    rb_sprintf(gamma, "%u.%u", a, b);
    rb_sprintf(outbuf, "%s.%s.%s:i4msk", do_ip_cloak_part(alpha), do_ip_cloak_part(beta), do_ip_cloak_part(gamma));
}

static void
do_host_cloak_ipv6(const char *inbuf, char *outbuf)
{
    unsigned char *a, *b, *c, *d;
    char buf[512], *alpha, *beta, *gamma;
    struct in6_addr in_addr;
    a = rb_malloc(512);
    b = rb_malloc(512);
    c = rb_malloc(512);
    alpha = rb_malloc(512);
    beta = rb_malloc(512);
    gamma = rb_malloc(512);
    rb_inet_pton(AF_INET6, inbuf, &in_addr);
    rb_sprintf(c, "%2x%2x.%2x%2x.%2x%2x.%2x%2x.%2x%2x.%2x%2x",
		in_addr.s6_addr[0],
		in_addr.s6_addr[1],
		in_addr.s6_addr[2],
		in_addr.s6_addr[3],
		in_addr.s6_addr[4],
		in_addr.s6_addr[5],
		in_addr.s6_addr[6],
		in_addr.s6_addr[7],
		in_addr.s6_addr[8],
		in_addr.s6_addr[9],
		in_addr.s6_addr[10],
		in_addr.s6_addr[11]
	);
    rb_sprintf(b, "%2x%2x.%2x%2x.%2x%2x.%2x%2x",
		in_addr.s6_addr[0],
		in_addr.s6_addr[1],
		in_addr.s6_addr[2],
		in_addr.s6_addr[3],
		in_addr.s6_addr[4],
		in_addr.s6_addr[5],
		in_addr.s6_addr[6],
		in_addr.s6_addr[7]
	);
    rb_sprintf(a, "%2x%2x.%2x%2x",
		in_addr.s6_addr[0],
		in_addr.s6_addr[1],
		in_addr.s6_addr[2],
		in_addr.s6_addr[3]
	);
    rb_sprintf(alpha, "%s", inbuf);
    rb_sprintf(beta, "%s.%s.%s", a, b, c);
    rb_sprintf(gamma, "%s.%s", a, b);
    rb_sprintf(outbuf, "%s:%s:%s:i6msk", do_ip_cloak_part(alpha), do_ip_cloak_part(beta), do_ip_cloak_part(gamma));
}

static void
distribute_hostchange(struct Client *client_p, char *newhost)
{
    if (newhost != client_p->orighost)
        sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
                           newhost);
    else
        sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :hostname reset",
                           newhost);

    sendto_server(NULL, NULL,
                  CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
                  use_id(&me), use_id(client_p), newhost);
    sendto_server(NULL, NULL,
                  CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
                  use_id(&me), use_id(client_p), newhost);

    change_nick_user_host(client_p, client_p->name, client_p->username, newhost, 0, "Changing host");

    if (newhost != client_p->orighost)
        SetDynSpoof(client_p);
    else
        ClearDynSpoof(client_p);
}

static void
do_host_cloak_host(const char *inbuf, char *outbuf)
{
    unsigned char *hash;
    char buf[3];
    char output[HOSTLEN+1];
    int i, j;

    hash = do_cloak_part(inbuf);

    output[0]=0;

    char *oldhost;
    j = 0;
    oldhost = rb_strdup(inbuf);
    int hostlen = 0;

    for (i = 0; i < strlen(oldhost); i++) {
        oldhost++;
        hostlen++;
        if (*oldhost == '.') {
            break;
        }
    }

    for (i = 0; i < 31; i = i + 1) {
        if (i >= hostlen && i >= 9) break;
        sprintf(buf, "%c", hash[i]);
        strcat(output,buf);
    }

    rb_strlcpy(outbuf,cloakprefix,HOSTLEN+1);
    rb_strlcat(outbuf,output,HOSTLEN+1);
    rb_strlcat(outbuf,oldhost,HOSTLEN+1);
}

static void
do_host_cloak_ip(const char *inbuf, char *outbuf)
{
    /* None of the characters in this table can be valid in an IP */
    char chartable[] = "ghijklmnopqrstuvwxyz";
    char *tptr;
    int sepcount = 0;
    int totalcount = 0;
    int ipv6 = 0;

    if (strchr(inbuf, ':')) {
        ipv6 = 1;

        /* Damn you IPv6...
         * We count the number of colons so we can calculate how much
         * of the host to cloak. This is because some hostmasks may not
         * have as many octets as we'd like.
         *
         * We have to do this ahead of time because doing this during
         * the actual cloaking would get ugly
         */
        for (tptr = inbuf; *tptr != '\0'; tptr++)
            if (*tptr == ':')
                totalcount++;
    } else if (!strchr(inbuf, '.'))
        return;
    if (ipv6)
       do_host_cloak_ipv6(inbuf, outbuf);
    else
       do_ip_cloak(inbuf, outbuf);
}

static void
check_umode_change(void *vdata)
{
    hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
    struct Client *source_p = data->client;

    if (!MyClient(source_p))
        return;

    /* didn't change +h umode, we don't need to do anything */
    if (!((data->oldumodes ^ source_p->umodes) & user_modes['x']))
        return;

    if (source_p->umodes & user_modes['x']) {
        if (IsIPSpoof(source_p) || source_p->localClient->mangledhost == NULL || (IsDynSpoof(source_p) && strcmp(source_p->host, source_p->localClient->mangledhost))) {
            source_p->umodes &= ~user_modes['x'];
            return;
        }
        if (strcmp(source_p->host, source_p->localClient->mangledhost)) {
            distribute_hostchange(source_p, source_p->localClient->mangledhost);
        } else /* not really nice, but we need to send this numeric here */
            sendto_one_numeric(source_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
                               source_p->host);
    } else if (!(source_p->umodes & user_modes['x'])) {
        if (source_p->localClient->mangledhost != NULL &&
            !strcmp(source_p->host, source_p->localClient->mangledhost)) {
            distribute_hostchange(source_p, source_p->orighost);
        }
    }
}

static void
check_new_user(void *vdata)
{
    struct Client *source_p = (void *)vdata;

    if (IsIPSpoof(source_p)) {
        source_p->umodes &= ~user_modes['x'];
        return;
    }
    source_p->localClient->mangledhost = rb_malloc(HOSTLEN + 1);
    if (!irccmp(source_p->orighost, source_p->sockhost))
        do_host_cloak_ip(source_p->orighost, source_p->localClient->mangledhost);
    else
        do_host_cloak_host(source_p->orighost, source_p->localClient->mangledhost);
    if (IsDynSpoof(source_p))
        source_p->umodes &= ~user_modes['x'];
    if (source_p->umodes & user_modes['x']) {
        rb_strlcpy(source_p->host, source_p->localClient->mangledhost, sizeof(source_p->host));
        if (irccmp(source_p->host, source_p->orighost))
            SetDynSpoof(source_p);
    }
}
