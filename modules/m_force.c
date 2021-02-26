/* contrib/m_force.c
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2004 ircd-ratbox Development Team
 * Maybe (C) Elemental-IRCd?
 * part of ircd-chatd in this modified form
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1.Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  2.Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  3.The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "stdinc.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "match.h"
#include "ircd.h"
#include "hostmask.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "logger.h"
#include "send.h"
#include "hash.h"
#include "s_serv.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"

static int mo_forcejoin(struct Client *client_p, struct Client *source_p,
                        int parc, const char *parv[]);
static int me_svsjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message forcejoin_msgtab = {
    "FORCEJOIN", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, {mo_forcejoin, 3}, mg_ignore, mg_ignore, {mo_forcejoin, 3}}
};

struct Message svsjoin_msgtab = {
    "SVSJOIN", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, {mo_forcejoin, 3}, mg_ignore, {me_svsjoin, 3}, {mo_forcejoin, 3}}
};

mapi_clist_av1 force_clist[] = { &forcejoin_msgtab, &svsjoin_msgtab, NULL };


static int h_can_create_channel;
static int h_channel_join;


mapi_hlist_av1 force_hlist[] = {
	{ "can_create_channel", &h_can_create_channel },
	{ "channel_join", &h_channel_join },
	{ NULL, NULL },
};

DECLARE_MODULE_AV1(force, NULL, NULL, force_clist, force_hlist, NULL, "$Revision$");

/*
 * m_forcejoin
 *      parv[1] = user to force
 *      parv[2] = channel to force them into
 */
static int
mo_forcejoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    struct Channel *chptr;
    int type;
    char mode;
    char sjmode;
    char *newch;
    hook_data_channel_activity hook_info;

    if(!IsOperAdmin(source_p) && MyClient(source_p)) {
		// Do not check remote forcejoin; from a server we trust it always.
        sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
        return 0;
    }

    if((hunt_server(client_p, source_p, ":%s FORCEJOIN %s %s", 1, parc, parv)) != HUNTED_ISME) {
        sendto_one_notice(source_p, ":*** Hunting SVSJOIN for %s to %s",
                         parv[1], parv[2]);
        return 0;
    }

    /* if target_p is not existant, print message
     * to source_p and bail - scuzzy
     */
    if((target_p = find_client(parv[1])) == NULL) {
        sendto_one(source_p, form_str(ERR_NOSUCHNICK), me.name, source_p->name, parv[1]);
        return 0;
    }

    if(!IsPerson(target_p))
        return 0;

    sendto_wallops_flags(UMODE_WALLOP, &me,
                         "FORCEJOIN called for %s %s by %s!%s@%s",
                         parv[1], parv[2], source_p->name, source_p->username, source_p->host);
    ilog(L_MAIN, "FORCEJOIN called for %s %s by %s!%s@%s",
         parv[1], parv[2], source_p->name, source_p->username, source_p->host);
    sendto_server(NULL, NULL, NOCAPS, NOCAPS,
                  ":%s WALLOPS :FORCEJOIN called for %s %s by %s!%s@%s",
                  me.name, parv[1], parv[2],
                  source_p->name, source_p->username, source_p->host);

    /* select our modes from parv[2] if they exist... (chanop) */
    if(*parv[2] == '@') {
        type = CHFL_CHANOP;
        mode = 'o';
        sjmode = '@';
    } else if(*parv[2] == '+') {
        type = CHFL_VOICE;
        mode = 'v';
        sjmode = '+';
    } else if(*parv[2] == '~') {
        type = CHFL_MANAGER;
        mode = 'q';
        sjmode = '~';
    } else if(*parv[2] == '*') {
        type = CHFL_OPERBIZ;
        mode = 'y';
        sjmode = '~';
    } else if(*parv[2] == '!') {
        type = CHFL_SUPEROP;
        mode = 'a';
        sjmode = '&';
    } else if(*parv[2] == '%') {
        type = CHFL_HALFOP;
        mode = 'h';
        sjmode = '%';
    } else {
        type = CHFL_PEON;
        mode = sjmode = '\0';
    }

    if(mode != '\0')
        parv[2]++;

    if((chptr = find_channel(parv[2])) != NULL) {
        if(IsMember(target_p, chptr)) {
            /* debugging is fun... */
            sendto_one_notice(source_p, ":*** Notice -- %s is already in %s",
                              target_p->name, chptr->chname);
            return 0;
        }

        add_user_to_channel(chptr, target_p, type);

        sendto_server(NULL, chptr, NOCAPS, NOCAPS,
                      type ? ":%s SJOIN %ld %s + :%c%s" : ":%s SJOIN %ld %s + :%s%s",
                      me.id, (long) chptr->channelts,
                      chptr->chname, type ? sjmode : "", target_p->id);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

        if(type)
            sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s +%c %s",
                                 me.name, chptr->chname, mode, target_p->name);

        if(chptr->topic != NULL) {
            sendto_one(target_p, form_str(RPL_TOPIC), me.name,
                       target_p->id, chptr->chname, chptr->topic);
            sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
                       me.name, source_p->name, chptr->chname,
                       chptr->topic_info, chptr->topic_time);
        }

        channel_member_names(chptr, target_p, 1, 0);
    } else {
        newch = LOCAL_COPY(parv[2]);
        if(!check_channel_name(newch)) {
            sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
                       source_p->name, (unsigned char *) newch);
            return 0;
        }

        /* channel name must be valid */
        if(!IsChannelName(newch)) {
            sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
                       source_p->name, (unsigned char *) newch);
            return 0;
        }

        /* newch can't be longer than CHANNELLEN */
        if(strlen(newch) > CHANNELLEN) {
            sendto_one_notice(source_p, ":Channel name is too long");
            return 0;
        }

        chptr = get_or_create_channel(target_p, newch, NULL);
	chptr->channelts = rb_current_time();
        add_user_to_channel(chptr, target_p, type);
	chptr->mode.mode |= ChannelHasModes(newch) ?
		ConfigChannel.autochanmodes :
		ConfigChannel.modelessmodes;
	const char *modes = channel_modes(chptr, &me);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

	sendto_channel_local(ONLY_CHANOPS, chptr, ":%s MODE %s %s",
		     me.name, chptr->chname, modes);

	sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
		      sjmode!=0 ? ":%s SJOIN %ld %s %s :%c%s" : ":%s SJOIN %ld %s %s :%s%s",
		      me.id, (long) chptr->channelts,
		      chptr->chname, modes, sjmode!=0 ? sjmode : "", target_p->id);
        target_p->localClient->last_join_time = rb_current_time();
        del_invite(chptr, target_p);

	if(chptr->topic != NULL)
	{
		sendto_one(target_p, form_str(RPL_TOPIC), me.name,
			   target_p->name, chptr->chname, chptr->topic);
			sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
			   me.name, target_p->name, chptr->chname,
			   chptr->topic_info, chptr->topic_time);
	}

	channel_member_names(chptr, target_p, 1, 0);
	hook_info.client = target_p;
	hook_info.chptr = chptr;
	hook_info.key = NULL;
	call_hook(h_channel_join, &hook_info);
        target_p->localClient->last_join_time = rb_current_time();

        /* we do this to let the oper know that a channel was created, this will be
         * seen from the server handling the command instead of the server that
         * the oper is on.
         */
        sendto_one_notice(source_p, ":*** Notice -- Creating channel %s", chptr->chname);
    }
    return 0;
}

/*
 * me_svsjoin - quiet forcejoin
 *      parv[1] = user to force
 *      parv[2] = channel to force them into
 */
static int
me_svsjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    struct Channel *chptr;
    int type;
    char mode;
    char sjmode;
    char *newch;
    hook_data_channel_activity hook_info;

    if(!(source_p->flags & FLAGS_SERVICE)) {
        return 0;
    }

    /* if target_p is not existant, print message
     * to source_p and bail - scuzzy
     */
    if((target_p = find_client(parv[1])) == NULL) {
        return 0;
    }

    if(!IsPerson(target_p))
        return 0;

    if(!MyClient(target_p))
        return 0;

    /* select our modes from parv[2] if they exist... (chanop) */
    if(*parv[2] == '@') {
        type = CHFL_CHANOP;
        mode = 'o';
        sjmode = '@';
    } else if(*parv[2] == '+') {
        type = CHFL_VOICE;
        mode = 'v';
        sjmode = '+';
    } else if(*parv[2] == '~') {
        type = CHFL_MANAGER;
        mode = 'q';
        sjmode = '~';
    } else if(*parv[2] == '!') {
        type = CHFL_OPERBIZ;
        mode = 'y';
        sjmode = '!';
    } else if(*parv[2] == '&') {
        type = CHFL_SUPEROP;
        mode = 'a';
        sjmode = '&';
    } else if(*parv[2] == '%') {
        type = CHFL_HALFOP;
        mode = 'h';
        sjmode = '%';
    } else if(*parv[2] == '+') {
        type = CHFL_VOICE;
        mode = 'v';
        sjmode = '+';
    } else {
        type = CHFL_PEON;
        mode = sjmode = '\0';
    }

    if(mode != '\0')
        parv[2]++;

    if((chptr = find_channel(parv[2])) != NULL) {
        if(IsMember(target_p, chptr)) {
            /* debugging is fun... */
            return 0;
        }

        add_user_to_channel(chptr, target_p, type);

        sendto_server(NULL, chptr, NOCAPS, NOCAPS,
                      type ? ":%s SJOIN %ld %s + :%c%s" : ":%s SJOIN %ld %s + :%s%s",
                      me.id, (long) chptr->channelts,
                      chptr->chname, type ? sjmode : "", target_p->id);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

        if(type)
            sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s +%c %s",
                                 me.name, chptr->chname, mode, target_p->name);
    } else {
        newch = LOCAL_COPY(parv[2]);
        if(!check_channel_name(newch)) {
            return 0;
        }

        /* channel name must begin with & or # */
        if(!IsChannelName(newch)) {
            return 0;
        }

        /* newch can't be longer than CHANNELLEN */
        if(strlen(newch) > CHANNELLEN) {
            return 0;
        }

        chptr = get_or_create_channel(target_p, newch, NULL);
	chptr->channelts = rb_current_time();
        add_user_to_channel(chptr, target_p, type);
	chptr->mode.mode |= ChannelHasModes(newch) ?
		ConfigChannel.autochanmodes :
		ConfigChannel.modelessmodes;
	const char *modes = channel_modes(chptr, &me);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

	sendto_channel_local(ONLY_CHANOPS, chptr, ":%s MODE %s %s",
		     me.name, chptr->chname, modes);

	sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
		      type ? ":%s SJOIN %ld %s %s :%c%s" : ":%s SJOIN %ld %s %s :%s%s",
		      me.id, (long) chptr->channelts,
		      chptr->chname, modes, type ? sjmode : "", target_p->id);

    }
        target_p->localClient->last_join_time = rb_current_time();
    del_invite(chptr, target_p);

	if(chptr->topic != NULL)
	{
		sendto_one(target_p, form_str(RPL_TOPIC), me.name,
			   target_p->name, chptr->chname, chptr->topic);
			sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
			   me.name, target_p->name, chptr->chname,
			   chptr->topic_info, chptr->topic_time);
	}

	channel_member_names(chptr, target_p, 1, 0);
	hook_info.client = target_p;
	hook_info.chptr = chptr;
	hook_info.key = NULL;
	call_hook(h_channel_join, &hook_info);
    return 0;
}
