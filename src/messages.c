
#include "stdinc.h"
#include "s_user.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "listener.h"
#include "msg.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "logger.h"
#include "s_serv.h"
#include "s_stats.h"
#include "scache.h"
#include "send.h"
#include "supported.h"
#include "whowas.h"
#include "packet.h"
#include "reject.h"
#include "cache.h"
#include "hook.h"
#include "monitor.h"
#include "snomask.h"
#include "blacklist.h"
#include "substitution.h"
#include "chmode.h"
#include "s_assert.h"
#include "messages.h"

// here's the rules: up to 50 variants, first ten are internal, 11-50 are language banks.

char * numerics [51001];

char *form_str(int number)
{
	if (numerics[number] == NULL || 0 == strlen(numerics[number]))
		return ":This error should NEVER. EVER. Happen. I hope you speak English.";
	return numerics[number];
};

char *vform_str(int number, int variant)
{
	return form_str((variant*1000)+number);
};

void prepare_numerics(void) {

numerics[51000] = NULL;

numerics[1] = ":Welcome to the %s Internet Relay Chat Network %s";
numerics[2] = ":Your host is %s, running version %s";
numerics[3] = ":This server was created %s";
numerics[4] = "%s %s %s %s qaohvbeIMkljfy";
numerics[5] = "%s :are supported by this server";
numerics[8] = "%s :Server notice mask";
numerics[10] = "%s %d :Please use this Server/Port instead";
numerics[15] = ":%s";
numerics[17] = ":End of /MAP";
numerics[43] = "%s :Nick collision, forcing nick change to your unique ID";
numerics[200] = "Link %s %s %s";
numerics[201] = "Try. %s %s";
numerics[202] = "H.S. %s %s";
numerics[203] = "???? %s %s (%s) %lu";
numerics[204] = "Oper %s %s (%s) %lu %lu";
numerics[205] = "User %s %s (%s) %lu %lu";
numerics[206] = "Serv %s %dS %dC %s %s!%s@%s %lu";
numerics[208] = "<newtype> 0 %s";
numerics[209] = "Class %s %d";
numerics[212] = "%s %u %lu :%u";
numerics[213] = "C %s %s %s %d %s";
numerics[215] = "I %s %s %s@%s %d %s";
numerics[216] = "%c %s * %s :%s%s%s";
numerics[217] = "%c %d %s :%s";
numerics[218] = "Y %s %d %d %d %u %d.%d %d.%d %u";
numerics[219] = "%c :End of /STATS report";
numerics[220] = "%c %d %s %d :%s%s";
numerics[221] = "%s";
numerics[225] = "%c %s :%s%s%s";
numerics[241] = "L %s * %s 0 -1";
numerics[242] = ":Server Up %d days, %d:%02d:%02d";
numerics[243] = "O %s@%s * %s %s %s";
numerics[244] = "H %s * %s 0 -1";
numerics[247] = "%c %d %s :%s";

numerics[248] = "U %s %s@%s %s";
numerics[250] = ":Highest connection count: %d (%d clients) (%lu connections received)";
numerics[251] = ":There are %d users and %d invisible on %d servers";
numerics[252] = "%d :IRC Operators online";
numerics[253] = "%d :unknown connection(s)";
numerics[254] = "%lu :channels formed";
numerics[255] = ":I have %d clients and %d servers";
numerics[256] = "%s :Administrative info";
numerics[257] = ":%s";
numerics[258] = ":%s";
numerics[259] = ":%s";
numerics[262] = "%s :End of TRACE";
numerics[263] = ":%s 263 %s %s :This command could not be completed because it has been used recently, and is rate-limited.";
numerics[265] = "%d %d :Current local users %d, max %d";
numerics[266] = "%d %d :Current global users %d, max %d";
numerics[270] = "%s :%s";
numerics[276] = "%s :has client certificate fingerprint %s";
numerics[281] = ":%s 281 %s %s";
numerics[282] = ":%s 282 %s :End of /ACCEPT list.";
numerics[301] = "%s :%s";
numerics[302] = ":%s 302 %s :%s";
numerics[303] = ":%s 303 %s :";
numerics[305] = ":You are no longer marked as being away";
numerics[306] = ":You have been marked as being away";
numerics[311] = "%s %s %s * :%s";
numerics[312] = "%s %s :%s";
numerics[313] = "%s :%s";
numerics[314] = ":%s 314 %s %s %s %s * :%s";
numerics[315] = ":%s 315 %s %s :End of /WHO list.";
numerics[317] = "%s %ld %lu :seconds idle, signon time";
numerics[318] = "%s :End of /WHOIS list.";
numerics[319] = ":%s 319 %s %s :";
numerics[320] = "%s :%s";
numerics[321] = ":%s 321 %s Channel :Users  Name";
numerics[322] = ":%s 322 %s %s%s %lu :%s";
numerics[323] = ":%s 323 %s :End of /LIST";
numerics[324] = ":%s 324 %s %s %s";
numerics[325] = ":%s 325 %s %s %s :is the current channel mode-lock";
numerics[329] = ":%s 329 %s %s %lu";
numerics[330] = "%s %s :is logged in as";
numerics[331] = ":%s 331 %s %s :No topic is set.";
numerics[332] = ":%s 332 %s %s :%s";
numerics[333] = ":%s 333 %s %s %s %lu";
numerics[337] = "%s :%s";
numerics[338] = "%s %s :actually using host";
numerics[341] = ":%s 341 %s %s %s";
numerics[346] = ":%s 346 %s %s %s %s %lu";
numerics[347] = ":%s 347 %s %s :End of Channel Invite List";
numerics[348] = ":%s 348 %s %s %s %s %lu";
numerics[349] = ":%s 349 %s %s :End of Channel Exception List";
#ifndef CUSTOM_BRANDING
numerics[351] = "%s(%s). %s :%s TS%dow %s";
#else
numerics[351] = "%s(%s,%s). %s :%s TS%dow %s";
#endif
numerics[352] = ":%s 352 %s %s %s %s %s %s %s :%d %s";
numerics[353] = ":%s 353 %s %s %s :";
numerics[355] = ":%s 355 %s %s %s :";
numerics[360] = ":%s 360 %s %s :was connecting from *@%s %s";
numerics[362] = ":%s 362 %s %s :Closed. Status = %d";
numerics[363] = ":%s 363 %s %d :Connections Closed";
numerics[364] = "%s %s :%d %s";
numerics[365] = "%s :End of /LINKS list.";
numerics[366] = ":%s 366 %s %s :End of /NAMES list.";
numerics[367] = ":%s 367 %s %s %s %s %lu";
numerics[368] = ":%s 368 %s %s :End of Channel Ban List";
numerics[369] = ":%s 369 %s %s :End of WHOWAS";
numerics[371] = ":%s";
numerics[372] = ":%s 372 %s :- %s";
numerics[374] = ":End of /INFO list.";
numerics[375] = ":%s 375 %s :- %s Message of the Day - ";
numerics[376] = ":%s 376 %s :End of /MOTD command.";
numerics[378] = "%s :is connecting from *@%s %s";
numerics[381] = ":%s 381 %s :We would like to take this moment to remind you that we accept absolutely no liability for the insanity you're about to endure.";
numerics[382] = ":%s 382 %s %s :Rehashing";
numerics[386] = ":%s 386 %s :%s";
numerics[391] = "%s :%s";
numerics[401] = "%s :No such nick/channel";
numerics[402] = "%s :No such server";
numerics[403] = "%s :No such channel";
numerics[404] = "%s :Cannot send to channel";
numerics[405] = ":%s 405 %s %s :You have joined too many channels";
numerics[406] = ":%s 406 %s %s :There was no such nickname";
numerics[407] = ":%s 407 %s %s :Too many recipients.";
numerics[409] = ":%s 409 %s :No origin specified";
numerics[410] = ":%s 410 %s %s :Invalid CAP subcommand";
numerics[411] = ":%s 411 %s :No recipient given (%s)";
numerics[412] = ":%s 412 %s :No text to send";
numerics[413] = "%s :No toplevel domain specified";
numerics[414] = "%s :Wildcard in toplevel Domain";
numerics[416] = ":%s 416 %s %s :output too large, truncated";
numerics[421] = ":%s 421 %s %s :Unknown command";
numerics[422] = ":%s 422 %s :MOTD File is missing";
numerics[431] = ":%s 431 %s :No nickname given";
numerics[432] = ":%s 432 %s %s :Erroneous Nickname";
numerics[433] = ":%s 433 %s %s :Nickname is already in use.";
numerics[435] = "%s %s :Cannot change nickname while banned on channel";
numerics[436] = "%s :Nickname collision KILL";
numerics[437] = ":%s 437 %s %s :Nick/channel is temporarily unavailable";
numerics[438] = ":%s 438 %s %s %s :Nick change too fast. Please wait %d seconds.";
numerics[440] = "%s :Services are currently unavailable";
numerics[441] = "%s %s :They aren't on that channel";
numerics[442] = "%s :You're not on that channel";
numerics[443] = "%s %s :is already on channel";
numerics[451] = ":%s 451 * :You have not registered";
numerics[456] = ":%s 456 %s :Accept list is full";
numerics[457] = ":%s 457 %s %s :is already on your accept list";
numerics[458] = ":%s 458 %s %s :is not on your accept list";
numerics[461] = ":%s 461 %s %s :Not enough parameters";
numerics[462] = ":%s 462 %s :You may not reregister";
numerics[464] = ":%s 464 %s :Password Incorrect";
numerics[465] = ":%s 465 %s :You are banned from this server- %s";
numerics[470] = "%s %s :Forwarding to another channel";
numerics[471] = ":%s 471 %s %s :Cannot join channel (+l) - channel is full, try again later";
numerics[472] = ":%s 472 %s %c :is an unknown mode char to me";
numerics[473] = ":%s 473 %s %s :Cannot join channel (+i) - you must be invited";
numerics[474] = ":%s 474 %s %s :Cannot join channel (+b) - you are banned";
numerics[475] = ":%s 475 %s %s :Cannot join channel (+k) - bad key";
numerics[477] = ":%s 477 %s %s :Cannot join channel (+R) - you need to be identified with services";
numerics[478] = ":%s 478 %s %s %s :Channel ban list is full";
numerics[479] = "%s :Illegal channel name";
numerics[480] = ":%s 480 %s %s :Cannot join channel (+j) - throttle exceeded, try again later";
numerics[481] = ":Permission Denied - You're not an IRC operator";
numerics[482] = ":%s 482 %s %s :You're not a channel operator";
numerics[1482] = ":%s 482 %s %s :You're insufficiently privileged on this channel.";
numerics[2482] = ":%s 482 %s %s :You're not at least a channel half-operator";
numerics[3482] = ":%s 482 %s %s :You're not at least a channel operator";
numerics[4482] = ":%s 482 %s %s :You're not a channel operator";
numerics[5482] = ":%s 482 %s %s :You're not a channel operator";
numerics[483] = ":You can't kill a server!";
numerics[484] = ":%s 484 %s %s %s :Cannot kick or deop a network service";
numerics[486] = "%s :You must log in with services to message this user";
numerics[496] = "%s :You must be an IRC Operator to message this user";
numerics[497] = "%s :You must be connected using SSL/TLS to message this user";
numerics[489] = ":%s 489 %s %s :You're neither voiced nor channel operator";
numerics[491] = ":No appropriate operator blocks were found for your host";
numerics[494] = "%s :cannot answer you while you are %s, your message was not sent";
numerics[501] = ":%s 501 %s :Unknown MODE flag";
numerics[502] = ":%s 502 %s :Can't change mode for other users";
numerics[504] = ":%s 504 %s %s :User is not on this server";
numerics[513] = ":%s 513 %s :To connect type /QUOTE PONG %08lX";
numerics[517] = "%s :This command has been administratively disabled";
numerics[524] = ":%s 524 %s %s :Help not found";
numerics[670] = ":STARTTLS successful, proceed with TLS handshake";
numerics[671] = "%s :%s";
numerics[691] = ":%s";
numerics[702] = ":%s 702 %s %s 0x%lx %s %s";
numerics[703] = ":%s 703 %s :End of /MODLIST.";
numerics[704] = ":%s 704 %s %s :%s";
numerics[705] = ":%s 705 %s %s :%s";
numerics[706] = ":%s 706 %s %s :End of /HELP.";
numerics[707] = ":%s 707 %s %s :Targets changing too fast, message dropped";
numerics[708] = ":%s 708 %s %s %s %s %s %s %s %s :%s";
numerics[709] = ":%s 709 %s %s %s %s %s %s %s :%s";
numerics[710] = ":%s 710 %s %s %s!%s@%s :has asked for an invite.";
numerics[711] = ":%s 711 %s %s :Your KNOCK has been delivered.";
numerics[712] = ":%s 712 %s %s :Too many KNOCKs (%s).";
numerics[713] = "%s :Channel is open.";
numerics[714] = ":%s 714 %s %s :You are already on that channel.";
numerics[715] = ":%s 715 %s :KNOCKs are disabled.";

numerics[716] = "%s :is in +g mode (server-side ignore.)";
numerics[717] = "%s :has been informed that you messaged them.";
numerics[718] = ":%s 718 %s %s %s@%s :is messaging you, and you have umode +g.";

// Preset variants, used by optional modules:
numerics[1716] = "%s :is in +G mode, which is server-side ignore with an exception for those in common channels.";
numerics[1717] = "%s :You are not in any channels that the other person is in, therefore, your message has not been delivered. The other user has been notified, however.";
numerics[1718] = ":%s 718 %s %s %s@%s :is messaging you, and you have umode +G.";

numerics[2716] = "%s :is in +G mode, which is server-side ignore with an exception for those in common channels.";
numerics[2717] = "%s :You are not in any channels that the other person is in, therefore, your message has not been delivered. The other user has been notified, however.";
numerics[2718] = ":%s 718 %s %s %s@%s :is messaging you, and you have umode +t.";

numerics[3716] = "%s :is in +%s mode - %s.";
numerics[3717] = "%s :has been informed that you messaged them. %s";
numerics[3718] = ":%s 718 %s %s %s@%s :is messaging you, and you have umode +%s (%s).";

numerics[720] = ":%s 720 %s :Start of OPER MOTD";
numerics[721] = ":%s 721 %s :%s";
numerics[722] = ":%s 722 %s :End of OPER MOTD";
numerics[723] = ":%s 723 %s %s :Insufficient oper privs";
numerics[725] = ":%s 725 %s %c %ld %s :%s";
numerics[726] = ":%s 726 %s %s :No matches";
numerics[727] = ":%s 727 %s %d %d %s!%s@%s %s :Local/remote clients match";
numerics[728] = ":%s 728 %s %s q %s %s %lu";
numerics[729] = ":%s 729 %s %s q :End of Channel Quiet List";
numerics[730] = ":%s 730 %s :%s";
numerics[731] = ":%s 731 %s :%s";
numerics[732] = ":%s 732 %s :%s";
numerics[733] = ":%s 733 %s :End of MONITOR list";
numerics[734] = ":%s 734 %s %d %s :Monitor list is full";
numerics[740] = ":%s 740 %s :%s";
numerics[741] = ":%s 741 %s :End of CHALLENGE";
numerics[742] = "%s %c %s :MODE cannot be set due to channel having an active MLOCK restriction policy";
numerics[743] = "%s %c %s :Invalid ban mask";
numerics[750] = "%d :matches";
numerics[751] = "%s %s %s %s %s %s :%s";
numerics[900] = ":%s 900 %s %s!%s@%s %s :You are now logged in as %s";
numerics[901] = ":%s 901 %s %s!%s@%s :You are now logged out";
numerics[902] = ":%s 902 %s :You must use a nick assigned to you";
numerics[903] = ":%s 903 %s :SASL authentication successful";
numerics[904] = ":%s 904 %s :SASL authentication failed";
numerics[905] = ":%s 905 %s :SASL message too long";
numerics[906] = ":%s 906 %s :SASL authentication aborted";
numerics[907] = ":%s 907 %s :You have already completed SASL authentication";
numerics[908] = ":%s 908 %s %s :are available SASL mechanisms";

numerics[1998] = ":%s NOTICE %s :(\x02%s\x02) %s";
}
