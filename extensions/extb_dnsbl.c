/* dnsbl mark extban type: matches DNSBL'ed clients. */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"

static int _modinit(void);
static void _moddeinit(void);
static int eb_dnsblmark(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type);

DECLARE_MODULE_AV1(extb_dnsblmark, _modinit, _moddeinit, NULL, NULL, NULL, "$Revision$");

static int
_modinit(void)
{
	extban_table['d'] = eb_dnsblmark;

	return 0;
}

static void
_moddeinit(void)
{
	extban_table['d'] = NULL;
}

static int eb_dnsblmark(const char *data, struct Client *client_p,
		struct Channel *chptr, long mode_type)
{
	struct Metadata *md;
	// = user_metadata_find(client_p, "WEBIRCNAME");
        struct DictionaryIter iter;
	int ismatched = EXTBAN_NOMATCH;

        DICTIONARY_FOREACH(md, &iter, client_p->metadata)
        {
                if (
                        md->name[0] == 'D' &&
                        md->name[1] == 'N' &&
                        md->name[2] == 'S' &&
                        md->name[3] == 'B' &&
                        md->name[4] == 'L' &&
                        md->name[5] == ':'
                ) {
			if (data == NULL) {
				return EXTBAN_MATCH;
				break; // NOTREACHED
			}
			if (match(data, md->name + 6))
				ismatched = EXTBAN_MATCH;
                }
        }

	(void)chptr;
	(void)mode_type;
	return ismatched;
}
