/*
 * Copyright (C) 2006 Jilles Tjoelker
 * Copyright (C) 2006 Stephen Bennett <spb@gentoo.org>
 *
 * $Id$
 */

#include "stdinc.h"
#include "modules.h"
#include "numeric.h"
#include "client.h"
#include "irc_dictionary.h"
#include "ircd.h"
#include "send.h"
#include "s_user.h"
#include "s_serv.h"
#include "s_conf.h"
#include "s_newconf.h"

static int mo_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_svsnoop(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

static int do_grant(struct Client *source_p, struct Client *target_p, const char *new_privset, int fmult);

struct Message grant_msgtab = {
  "GRANT", 0, 0, 0, MFLG_SLOW,
  { mg_ignore, mg_not_oper, mg_ignore, mg_ignore, {me_grant, 3}, {mo_grant, 3}}
};

struct Message svsnoop_msgtab = {
  "SVSNOOP", 0, 0, 0, MFLG_SLOW,
  { mg_ignore, mg_not_oper, mg_ignore, mg_ignore, {me_svsnoop, 2}, mg_ignore}
};

int SvsNoOp = 0;

static void on_oper_up (hook_data_client *hdata);

mapi_clist_av1 grant_clist[] = { &grant_msgtab, &svsnoop_msgtab, NULL };
mapi_hfn_list_av1 grant_hfnlist[] = {
	{ "opering_up", (hookfn) on_oper_up },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(grant, NULL, NULL, grant_clist, NULL, grant_hfnlist, "$Revision$");

static void on_oper_up (hook_data_client *hdata)
{
	struct Client *client_p = hdata->client;

	if (SvsNoOp)
	{
		sendto_one_numeric(client_p, ERR_NOOPERHOST,
		":This server is under quarantine. Only remote opers and Services can provide oper access.");
		hdata->approved++;
	}
}

static int
mo_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	int floodmult = 65;

	if(!HasPrivilege(source_p, "oper:netadmin"))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "grant");
		return 0;
	}

	target_p = find_named_person(parv[1]);
	if (target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), parv[1]);
		return 0;
	}

	if (parv[parc-1][0] == '%')
	{
		sendto_one(source_p, ":%s NOTICE %s :Reserved character for"
			"IRCd internal purposes.", me.name, source_p->name);
		return 0;
	}

	if (parv[parc-1][0] == '!')
	{
		sendto_one(source_p, ":%s NOTICE %s :Reserved character for"
			"IRCd internal purposes.", me.name, source_p->name);
		return 0;
	}

	if (parc >= 4) {
		floodmult = (unsigned int)strtoul(parv[parc-2], NULL, 10);
		if (floodmult > 64) floodmult = 65;
	}

	if (MyClient(target_p))
	{
		do_grant(source_p, target_p, parv[parc-1], floodmult > 64 ? -1 : floodmult);
	}
	else
	{
		sendto_one(target_p, ":%s ENCAP %s GRANT %s %u :%s",
				get_id(source_p, target_p), target_p->servptr->name,
				get_id(target_p, target_p), floodmult, parv[parc-1]);
	}

	return 0;
}

static int me_grant(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	int floodmult = 65;

	target_p = find_person(parv[1]);
	if (target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), parv[1]);
		return 0;
	}

	if (parv[parc-1][0] == '%')
	{
		sendto_one(source_p, ":%s NOTICE %s :Reserved character for"
			"IRCd internal purposes.", me.name, source_p->name);
		return 0;
	}

	if (parv[parc-1][0] == '!')
	{
		sendto_one(source_p, ":%s NOTICE %s :Reserved character for"
			"IRCd internal purposes.", me.name, source_p->name);
		return 0;
	}

	if (parc >= 4) {
		floodmult = (int)strtoul(parv[parc-2], NULL, 10);
	}
	if (floodmult > 64) floodmult = -1;

	if(!find_shared_conf(source_p->username, source_p->host,
				source_p->servptr->name, SHARED_GRANT) &&
		0 == (source_p->flags & FLAGS_SERVICE))
	{
		sendto_one(source_p, ":%s NOTICE %s :You don't have an appropriate shared"
			"block to grant privilege on this server.", me.name, source_p->name);
		return 0;
	}

	if (MyClient(target_p)) do_grant(source_p, target_p, parv[parc-1], floodmult);

	return 0;
}

static int me_svsnoop(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	// ENCAP * SVSNOOP +our.name
	// our name has to match that thing
	// ENCAP * SVSNOOP +* to deop everyone.

	char *sname;
	sname = (parv[1]) + 1;

	if (!match(sname, me.name))
		return 0;

	if (parv[1][0] == '+')
		SvsNoOp = 1;
	else if (parv[1][0] == '-')
		SvsNoOp = 0;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, lclient_list.head)
	{
		target_p = ptr->data;
		if (SvsNoOp) do_grant(source_p, target_p, "%deoper", target_p->localClient->att_conf->c_class->flood_multiplier);
	}

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s has %sed %s (mask: %s)%s.", source_p->name,
	       SvsNoOp ? "quarantin" : "releas", me.name, sname, SvsNoOp ? "" : " from quarantine");
	return 0;
}

static int do_grant(struct Client *source_p, struct Client *target_p, const char *new_privset, int fmult)
{
	int dooper = 0, dodeoper = 0;
	struct PrivilegeSet *privset = 0;
	char  privname[76];

	rb_snprintf(privname, 75, "!%s", use_id(target_p));

	if (!strcmp(new_privset, "deoper"))
	{
		if (!IsOper(target_p))
		{
			sendto_one_notice(source_p, ":You can't deoper someone who isn't an oper.");
			return 0;
		}
		new_privset = "default";
		dodeoper = 1;

		sendto_one_notice(target_p, ":%s is deopering you.", source_p->name);
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is deopering %s.", get_oper_name(source_p), target_p->name);
	}
	else if (*new_privset == '%')
	{
		if (!IsOper(target_p))
		{
			return 0;
		}
		new_privset = "default";
		privset = privilegeset_get(new_privset);
		dodeoper = 1;

		sendto_one_notice(target_p, ":%s is deopering you and everyone else on your server", source_p->name);
		sendto_one_notice(target_p, ":(\x02Notice\x02) This server is now under quarantine. Oper privileges may only be obtained if duly granted to users on this server by remote opers and Services.");
	}
	else
	{
		if (!(privset = privilegeset_set_new(privname, new_privset, 0)))
		{
			sendto_one_notice(source_p, ":Could not create privilege set containing the following privileges: %s", new_privset);
			return 0;
		}
		privilegeset_ref(privset);
	}

	if (!dodeoper)
	{
		if (!IsOper(target_p))
		{
			sendto_one_notice(target_p, ":%s has granted you operator privileges.", source_p->name);
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is opering %s", get_oper_name(source_p), target_p->name);
			dooper = 1;
		}
		else
		{
			sendto_one_notice(target_p, ":%s is changing your privileges to: %s", source_p->name, new_privset);
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "%s is changing the privileges of %s to: %s", get_oper_name(source_p), target_p->name, new_privset);
		}

		if (!IsOper(target_p))
		{
			dooper = 1;
		}
		else if (IsOper(target_p))
			dooper = dodeoper = 1;
	}

	if (dodeoper)
	{
		const char *modeparv[4];
		modeparv[0] = modeparv[1] = target_p->name;
		modeparv[2] = "-ohp";
		modeparv[3] = NULL;
		user_mode(target_p, target_p, 3, modeparv);
	}

	if (dooper)
	{
		struct oper_conf oper;
		oper.name = "<granted>";
		oper.umodes = 0;
		oper.vhost = NULL;
		oper.operstring = NULL;
		oper.swhois = NULL;
		oper.snomask = 0;
		oper.privset = privset;
		oper.flood_multiplier = fmult;

		oper_up(target_p, &oper);
	}

	target_p->localClient->privset = privset;
	const char *modeparv[4];
	modeparv[0] = modeparv[1] = target_p->name;
	modeparv[2] = "+";
	modeparv[3] = NULL;
	user_mode(target_p, target_p, 3, modeparv);

	return 0;
}
