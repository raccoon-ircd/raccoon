/*
 *  ircd-ratbox: A slightly useful ircd.
 *  listener.h: A header for the listener code.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2004 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *  $Id: listener.h 6 2005-09-10 01:02:21Z nenolod $
 */

#ifndef INCLUDED_listener_h
#define INCLUDED_listener_h

#include "ircd_defs.h"

struct Client;

struct Listener
{
	struct Listener *next;	/* list node pointer */
	const char *name;	/* listener name */
	rb_fde_t *F;		/* file descriptor */
	int ref_count;		/* number of connection references */
	int active;		/* current state of listener */
	int ssl;		/* ssl listener */
	int sctp;		// sctp listener
	int flags;		// it has been decided that it's better to use
				// flags than be embarrassed by the explosion here.
	int defer_accept;	/* use TCP_DEFER_ACCEPT */
	struct rb_sockaddr_storage addr;
	struct DNSQuery *dns_query;
	char vhost[HOSTLEN + 1];	/* virtual name of listener */
};

#define LISTENFLAG_SSL		0x00000001	// Listener uses SSL
#define LISTENFLAG_SCTP		0x00000002	// Listener uses SCTP
#define LISTENFLAG_ACTIVE	0x00000004	// Listener is being used
#define LISTENFLAG_DEFER	0x00000008	// Listener defers accepting.

#define ListenerIsSSL(l)	( ( (l)->flags & LISTENFLAG_SSL ) != 0x0 )
#define ListenerIsSCTP(l)	( (l)->sctp > 0 )
#define ListenerIsActive(l)	( ( (l)->flags & LISTENFLAG_ACTIVE ) != 0x0 )
#define ListenerDefersAccept(l)	( ( (l)->flags & LISTENFLAG_DEFER ) != 0x0 )

extern void add_listener(int port, const char *vaddr_ip, int family, int ssl, int defer_accept, int sctp);
extern void close_listener(struct Listener *listener);
extern void close_listeners(void);
extern const char *get_listener_name(const struct Listener *listener);
extern void show_ports(struct Client *client);
extern void free_listener(struct Listener *);

#endif /* INCLUDED_listener_h */
