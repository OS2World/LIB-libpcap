/*
 * Copyright (c) 1993, 1994, 1995, 1996
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
#ifndef lint
static  char rcsid[] =
    "@(#)$Header: pcap-snoop.c,v 1.15 96/07/15 00:48:52 leres Exp $ (LBL)";
#endif

#define INCL_BASE
#include <os2.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timeb.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>
#include <ipspy.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap-int.h"

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#define IPSPY_HANDLES 8
#define IPSPY_INVALID -1

static UCHAR IpSpy_Device[IPSPY_HANDLES][IFNAMSIZ+1] = {"", "", "", "", "", "", "", ""};
static ULONG IpSpy_Handle[IPSPY_HANDLES] = {IPSPY_INVALID, IPSPY_INVALID, IPSPY_INVALID, IPSPY_INVALID, IPSPY_INVALID, IPSPY_INVALID, IPSPY_INVALID, IPSPY_INVALID};
static USHORT IpSpy_OldMode[IPSPY_HANDLES];
static int IpSpy_Handles = 0;
static int IpSpy_Cleanup_Installed = 0;

static void IpSpy_Cleanup (void)
{
        APIRET rc;
        int i;

        for (i = 0; i < IPSPY_HANDLES; i++) {
          if (IpSpy_Handle[i] != IPSPY_INVALID) {
            if ((rc = IpSpy_Exit(IpSpy_Handle[i])) != RC_IPSPY_NOERROR)
              fprintf(stderr, "IpSpyExit error: %d\n", rc);

            if ((rc = IpSpy_SetReceiveMode(IpSpy_OldMode[i], IpSpy_Device[i], NULL)) != RC_IPSPY_NOERROR)
              fprintf(stderr, "IpSpy_SetReceiveMode error: %d\n", rc);

            fprintf(stderr, "IpSpy_Cleanup closed %s\n", IpSpy_Device[i]);

            strcpy(IpSpy_Device[i], "");
            IpSpy_Handle[i] = IPSPY_INVALID;
            IpSpy_Handles--;
          }
        }

        if (IpSpy_Handles != 0)
          fprintf(stderr, "IpSpy handle mismatch\n");

        fprintf(stderr, "IpSpy terminated\n");
}

int
pcap_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
static int seq = 0;
        register int datalen;
        register int caplen;
        register u_char *cp;

        APIRET rc;
        USHORT usLength, usType;
        ULONG  ulTimeStamp;
        ULONG  ulTime;
        USHORT usUnknown;

        usLength = p->bufsize;
        if ((rc = IpSpy_ReadRaw(p->fd, (char *)p->buffer, &usLength, &usType, &ulTimeStamp, &usUnknown)) != RC_IPSPY_NOERROR) {
          fprintf(stderr, "IpSpy_ReadRaw error: %d\n", rc);
          errno = EINVAL; /* bogus error code */
          sprintf(p->errbuf, "read: %s", pcap_strerror(errno));
          return (-1);
        }

        datalen = usLength;
        caplen = usLength;
        cp = p->buffer;

        if (p->fcode.bf_insns == NULL ||
            bpf_filter(p->fcode.bf_insns, cp, datalen, caplen)) {
                struct pcap_pkthdr h;
                struct timeb tb;
                ++p->md.stat.ps_recv;
                _ftime(&tb);
                h.ts.tv_sec = tb.time;
                h.ts.tv_usec = tb.millitm * 1000;
                h.len = datalen;
                h.caplen = caplen;
                (*callback)(user, &h, cp);
                return (1);
        }
        return (0);
}

int
pcap_stats(pcap_t *p, struct pcap_stat *ps)
{
        p->md.stat.ps_drop = 0;

/*          rs->rs_snoop.ss_ifdrops + rs->rs_snoop.ss_sbdrops +
            rs->rs_drain.ds_ifdrops + rs->rs_drain.ds_sbdrops; */

        *ps = p->md.stat;
        return (0);
}

pcap_t *
pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
{
        pcap_t *p;

        APIRET rc;
        UCHAR  *pVersion, **pIFs;
        ULONG  ulHandle = IPSPY_INVALID;
        USHORT usOldMode;
        UCHAR  *pSocketError;
        ULONG  ulSocketError;
        int i;

        p = (pcap_t *)malloc(sizeof(*p));
        if (p == NULL) {
                sprintf(ebuf, "malloc: %s", pcap_strerror(errno));
                return (NULL);
        }
        bzero((char *)p, sizeof(*p));

        if ((rc = IpSpy_Version(&pVersion)) != RC_IPSPY_NOERROR) {
          sprintf(ebuf, "IpSpy_Version error: %d\n", rc);
          goto bad;
        }
        else
          fprintf(stderr, "IpSpy Version: %s on device %s\n", pVersion, device);

        if (IpSpy_Handles < IPSPY_HANDLES) {
          for (i = 0; i < IPSPY_HANDLES; i++)
            if (IpSpy_Handle[i] == IPSPY_INVALID)
              break;
        }
        else {
          sprintf(ebuf, "IpSpy error: out of handles\n");
          goto bad;
        }

        if ((rc = IpSpy_QueryReceiveMode(&usOldMode, NULL)) != RC_IPSPY_NOERROR) {
          if (rc == RC_IPSPY_MODE_NOT_SUPPORTED)
            sprintf(ebuf, "IpSpy_QueryReceiveMode error: Promiscuous mode not supported\n");
          else if (rc == RC_IPSPY_CANNOT_OPEN_DRIVER)
            sprintf(ebuf, "IpSpy_QueryReceiveMode error: Cannot open IPSPY.OS2\n");
          else
            sprintf(ebuf, "IpSpy_QueryReceiveMode error: %d\n", rc);
          goto bad;
        }

        if ((rc = IpSpy_QueryInterfaces(&pIFs)) != RC_IPSPY_NOERROR) {
          sprintf(ebuf, "IpSpy_QueryInterfaces error: %d\n", rc);
          goto bad;
        } else {
          int i;
          fprintf(stderr, "IpSpy supported interfaces:");
          if (pIFs)
            for (i = 0; pIFs[i]; i++)
              fprintf(stderr, " %s", pIFs[i]);
          fprintf(stderr, "\n");
        }

        if (promisc)
          if ((rc = IpSpy_SetReceiveMode(DIRECTED_MODE | BROADCAST_MODE | PROMISCUOUS_MODE, device, NULL)) != RC_IPSPY_NOERROR) {
            if (rc == RC_IPSPY_MODE_NOT_SUPPORTED)
              sprintf(ebuf, "IpSpy: promiscuous mode not supported\n");
            else if (rc == RC_IPSPY_CANNOT_OPEN_DRIVER)
              sprintf(ebuf, "IpSpy_SetReceiveMode error: cannot open IPSPY.OS2\n");
            else
              sprintf(ebuf, "IpSpy_SetReceiveMode error: %d\n", rc);
            goto bad;
          }

        if ((rc = IpSpy_Init(&ulHandle, device)) != RC_IPSPY_NOERROR) {
          if (rc == RC_IPSPY_SOCKET_ERROR) {
            IpSpy_GetLastSocketError(&ulSocketError, &pSocketError);
            sprintf(ebuf, "IpSpy_Init socket error: [%d] %s\n", ulSocketError, pSocketError);
          }
          else
            sprintf(ebuf, "IpSpy_Init error: %d\n", rc);
          goto bad;
        }

        p->fd = ulHandle;
        p->snapshot = snaplen; /* no snaplen for IpSpy */
        /*
         * XXX hack - map device name to link layer type
         */
        if (strncmp("lan", device, 3) == 0) {
                p->linktype = DLT_EN10MB;
        } else if (strncmp("lo", device, 2) == 0) {
                p->linktype = DLT_RAW;
        } else if (strncmp("sl", device, 2) == 0) {
                p->linktype = DLT_SLIP_BSDOS;
        } else if (strncmp("ppp", device, 3) == 0) {
                p->linktype = DLT_PPP_BSDOS;
        } else {
                sprintf(ebuf, "IpSpy: unknown link layer type");
                goto bad;
        }

        p->bufsize = 4096;                              /* XXX */
        p->buffer = (u_char *)malloc(p->bufsize);
        if (p->buffer == NULL) {
                sprintf(ebuf, "malloc: %s", pcap_strerror(errno));
                goto bad;
        }

        strcpy(IpSpy_Device[i], device);
        IpSpy_Handle[i] = ulHandle;
        IpSpy_OldMode[i] = usOldMode;
        IpSpy_Handles++;
        if (!IpSpy_Cleanup_Installed)
          atexit(IpSpy_Cleanup);

        return (p);
bad:
        if (ulHandle != IPSPY_INVALID && (rc = IpSpy_Exit(ulHandle)) != RC_IPSPY_NOERROR)
          fprintf(stderr, "IpSpy_Exit error: %d\n", rc);
        free(p);
        return (NULL);
}

int
pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{

        p->fcode = *fp;
        return (0);
}

void
pcap_close(pcap_t *p)
{
        APIRET rc;
        int i;

        if (p->fd >= 0) {
          for (i = 0; i < IPSPY_HANDLES; i++)
            if (IpSpy_Handle[i] == p->fd) {
              if ((rc = IpSpy_Exit(p->fd)) != RC_IPSPY_NOERROR)
                fprintf(stderr, "IpSpyExit error: %d\n", rc);

              if ((rc = IpSpy_SetReceiveMode(IpSpy_OldMode[i], IpSpy_Device[i], NULL)) != RC_IPSPY_NOERROR)
                fprintf(stderr, "IpSpy_SetReceiveMode error: %d\n", rc);

              strcpy(IpSpy_Device[i], "");
              IpSpy_Handle[i] = IPSPY_INVALID;
              IpSpy_Handles--;

              goto cont;
            }
          fprintf(stderr, "IpSpy error: unknown handle\n");
        }
cont:
        if (p->sf.rfile != NULL) {
                (void)fclose(p->sf.rfile);
                if (p->sf.base != NULL)
                        free(p->sf.base);
        } else if (p->buffer != NULL)
                free(p->buffer);

        free(p);
}
