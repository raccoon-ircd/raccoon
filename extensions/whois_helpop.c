/*
 * "is available for help." for ircd-chatd.
 * modular for obvious reasons. (not worth coring it)
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
#include "privilege.h"
#include "s_newconf.h"
#include "newconf.h"

#define IsOperHelpop(x)	(HasPrivilege((x), "oper:helpop"))

static void h_helpop_whois(hook_data_client *);
static void h_helpop_high_whois(hook_data_client *);

static void check_umode_change(void *data);
char *helpopstring = "";
char helpoploc = 0;

#define IsUnrealStyle()	(helpoploc != 0)
#define IsChatdStyle()	(helpoploc == 0)

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	if (data->oldumodes & UMODE_OPER && !IsOper(source_p))
		source_p->umodes &= ~user_modes['h'];

	/* didn't change +p umode, we don't need to do anything */
	if (!((data->oldumodes ^ source_p->umodes) & user_modes['h']))
		return;

	if (source_p->umodes & user_modes['h'])
	{
		if (!IsOperHelpop(source_p))
		{
			sendto_one_notice(source_p, ":[Error] You need the privilege oper:helpop for this usermode to work.");
			source_p->umodes &= ~user_modes['h'];
			return;
		}

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s has marked themself available for help.",
				       get_oper_name(source_p));
	}
}

static void
conf_set_helpopstring(void *data)
{
	helpopstring = rb_strdup(data);
}

static void
conf_set_helpoploc(void *data)
{
	helpoploc = *(unsigned int *)data;
}

static void
helpop_whois(hook_data_client *data)
{
	if(!EmptyString(helpopstring) && (data->target->umodes & user_modes['h']) != 0x0)
	{
		sendto_one_numeric(data->client, RPL_WHOISSPECIAL,
				form_str(RPL_WHOISSPECIAL),
				data->target->name, helpopstring);
	}
}

static void h_helpop_whois (hook_data_client *data)
{
	if (IsChatdStyle()) helpop_whois(data);
}

static void h_helpop_high_whois (hook_data_client *data)
{
	if (IsUnrealStyle()) helpop_whois(data);
}

static int
_modinit(void)
{
	user_modes['h'] = find_umode_slot();
	user_mode_names['h'] = "helpop";

	/* add the usermode to the available slot */
	add_conf_item("network", "helpopstring", CF_QSTRING, conf_set_helpopstring);
	add_conf_item("network", "helpop_unreal_loc", CF_YESNO, conf_set_helpoploc);
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	user_modes['h'] = 0;
	user_mode_names['h'] = 0;

	/* disable the umode and remove it from the available list */
	remove_conf_item("network", "helpopstring");
	remove_conf_item("network", "helpop_unreal_loc");
	construct_umodebuf();
}
mapi_hfn_list_av1 whois_helpop_hfnlist[] = {
	{ "umode_changed", (hookfn) check_umode_change },
	{ "doing_whois",	(hookfn) h_helpop_whois },
	{ "doing_whois_global",	(hookfn) h_helpop_whois },
	{ "upper_doing_whois",	(hookfn) h_helpop_high_whois },
	{ "upper_doing_whois_global",	(hookfn) h_helpop_high_whois },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(whois_helpop, _modinit, _moddeinit, NULL, NULL,
			whois_helpop_hfnlist, "$Revision: 3526 $");

