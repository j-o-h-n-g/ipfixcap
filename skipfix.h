/*
** Copyright (C) 2007-2015 by Carnegie Mellon University.
**
** @OPENSOURCE_HEADER_START@
**
** Use of the SILK system and related source code is subject to the terms
** of the following licenses:
**
** GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
**
** NO WARRANTY
**
** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
** DELIVERABLES UNDER THIS LICENSE.
**
** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
** Mellon University, its trustees, officers, employees, and agents from
** all claims or demands made against them (and any related losses,
** expenses, or attorney's fees) arising out of, or relating to Licensee's
** and/or its sub licensees' negligent use or willful misuse of or
** negligent conduct or willful misconduct regarding the Software,
** facilities, or other rights or assistance granted by Carnegie Mellon
** University under this License, including, but not limited to, any
** claims of product liability, personal injury, death, damage to
** property, or violation of any laws or regulations.
**
** Carnegie Mellon University Software Engineering Institute authored
** documents are sponsored by the U.S. Department of Defense under
** Contract FA8721-05-C-0003. Carnegie Mellon University retains
** copyrights in all material produced under this contract. The U.S.
** Government retains a non-exclusive, royalty-free license to publish or
** reproduce these documents, or allow others to do so, for U.S.
** Government purposes only pursuant to the copyright license under the
** contract clause at 252.227.7013.
**
** @OPENSOURCE_HEADER_END@
*/

/*
**  skipfix.c
**
**    SiLK Flow Record / IPFIX translation core
**
**    Brian Trammell
**    February 2007
*/

#define LIBFLOWSOURCE_SOURCE 1
#include <silk/silk.h>

RCSIDENT("$SiLK: skipfix.c 0274717355c9 2015-09-15 15:17:12Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skipfix.h>
#include <silk/sklog.h>
#include <silk/skvector.h>
#include <silk/utils.h>

#ifdef SKIPFIX_TRACE_LEVEL
#define TRACEMSG_LEVEL 1
#endif
#define TRACEMSG(x)  TRACEMSG_TO_TRACEMSGLVL(1, x)
#include <silk/sktracemsg.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* The IPFIX Private Enterprise Number for CERT */
#define IPFIX_CERT_PEN  6871

/* Extenal Template ID used for SiLK Flows written by rwsilk2ipfix.
 * This is defined in skipfix.h. */
/* #define SKI_RWREC_TID        0xAFEA */

/* Internal Template ID for extended SiLK flows. */
#define SKI_EXTRWREC_TID        0xAFEB

/* Internal Template ID for TCP information. */
#define SKI_TCP_STML_TID        0xAFEC

/* Internal Template ID for NetFlowV9 Sampling Options Template */
#define SKI_NF9_SAMPLING_TID    0xAFED

/* Bit in Template ID that yaf sets for templates containing reverse
 * elements */
#define SKI_YAF_REVERSE_BIT     0x0010

/* Template ID used by yaf for a yaf stats option record */
#define SKI_YAF_STATS_TID       0xD000

/* Template ID used by yaf for a subTemplateMultiList containing only
 * forward TCP flags information. */
#define SKI_YAF_TCP_FLOW_TID    0xC003

/* Name of environment variable that, when set, cause SiLK to print
 * the templates that it receives to the log. */
#define SKI_ENV_PRINT_TEMPLATES  "SILK_IPFIX_PRINT_TEMPLATES"

/* The template's context pointer is a 64-bit bitmap.  This determines
 * whether to allocate the bitmap or to use a pointer itself and cast
 * the pointer to a uintptr_t. */
#ifndef SKIPFIX_ALLOCATE_BITMAP
#  if SK_SIZEOF_UINTPTR_T > 4
#    define SKIPFIX_ALLOCATE_BITMAP 0
#  else
#    define SKIPFIX_ALLOCATE_BITMAP 1
#  endif
#endif

/*
 *  val = CLAMP_VAL(val, max);
 *
 *    If 'val' is greater then 'max', return 'max'.  Otherwise,
 *    return (max & val).
 */
#define CLAMP_VAL(val, max) \
    (((val) > (max)) ? (max) : ((max) & (val)))

/* One more than UINT32_MAX */
#define ROLLOVER32 ((intmax_t)UINT32_MAX + 1)

/*
 *    For NetFlow V9, when the absolute value of the magnitude of the
 *    difference between the sysUpTime and the flowStartSysUpTime is
 *    greater than this value (in milliseconds), assume one of the
 *    values has rolled over.
 */
#define MAXIMUM_FLOW_TIME_DEVIATION  ((intmax_t)INT32_MAX)

/* Define the IPFIX information elements in IPFIX_CERT_PEN space for
 * SiLK */
fbInfoElement_t ski_info_elements[] = {
    /* Extra fields produced by yaf for SiLK records */
    FB_IE_INIT("initialTCPFlags",              IPFIX_CERT_PEN, 14,  1,
               FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("unionTCPFlags",                IPFIX_CERT_PEN, 15,  1,
               FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("reverseFlowDeltaMilliseconds", IPFIX_CERT_PEN, 21,  4,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("silkFlowType",                 IPFIX_CERT_PEN, 30,  1,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("silkFlowSensor",               IPFIX_CERT_PEN, 31,  2,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("silkTCPState",                 IPFIX_CERT_PEN, 32,  1,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("silkAppLabel",                 IPFIX_CERT_PEN, 33,  2,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("flowAttributes",               IPFIX_CERT_PEN, 40,  2,
               FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),

    /* Extra fields produced by yaf for yaf statistics */
    FB_IE_INIT("expiredFragmentCount",         IPFIX_CERT_PEN, 100, 4,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("assembledFragmentCount",       IPFIX_CERT_PEN, 101, 4,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("meanFlowRate",                 IPFIX_CERT_PEN, 102, 4,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("meanPacketRate",               IPFIX_CERT_PEN, 103, 4,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("flowTableFlushEventCount",     IPFIX_CERT_PEN, 104, 4,
               FB_IE_F_ENDIAN),
    FB_IE_INIT("flowTablePeakCount",           IPFIX_CERT_PEN, 105, 4,
               FB_IE_F_ENDIAN),
    FB_IE_NULL
};


/* These are IPFIX information elements either in the standard space
 * or specific to NetFlowV9.  However, these elements are not defined
 * in all versions of libfixbuf. */
fbInfoElement_t ski_std_info_elements[] = {
    FB_IE_NULL
};


/* Bytes of padding to add to ski_rwrec_spec and ski_rwrec_st to get a
 * multiple of 64bits */
#define SKI_RWREC_PADDING  6

/*
 * This is an IPFIX encoding of a standard SiLK Flow record (rwRec);
 * it is used for export by rwsilk2ipfix where it has Template ID
 * SKI_RWREC_TID.
 *
 * This also becomes part of the "Extended" record, ski_extrwrec_spec,
 * that is used for import.
 *
 * Keep this in sync with the ski_rwrec_t below.  Use
 * SKI_RWREC_PADDING to pad to 64bits. */
fbInfoElementSpec_t ski_rwrec_spec[] = {
    /* Millisecond start and end (epoch) (native time) */
    { (char*)"flowStartMilliseconds",              8, 0 },
    { (char*)"flowEndMilliseconds",                8, 0 },
    /* 4-tuple */
    { (char*)"sourceIPv6Address",                 16, 0 },
    { (char*)"destinationIPv6Address",            16, 0 },
    { (char*)"sourceIPv4Address",                  4, 0 },
    { (char*)"destinationIPv4Address",             4, 0 },
    { (char*)"sourceTransportPort",                2, 0 },
    { (char*)"destinationTransportPort",           2, 0 },
    /* Router interface information */
    { (char*)"ipNextHopIPv4Address",               4, 0 },
    { (char*)"ipNextHopIPv6Address",              16, 0 },
    { (char*)"ingressInterface",                   4, 0 },
    { (char*)"egressInterface",                    4, 0 },
    /* Counters (reduced length encoding for SiLK) */
    { (char*)"packetDeltaCount",                   8, 0 },
    { (char*)"octetDeltaCount",                    8, 0 },
    /* Protocol; sensor information */
    { (char*)"protocolIdentifier",                 1, 0 },
    { (char*)"silkFlowType",                       1, 0 },
    { (char*)"silkFlowSensor",                     2, 0 },
    /* Flags */
    { (char*)"tcpControlBits",                     1, 0 },
    { (char*)"initialTCPFlags",                    1, 0 },
    { (char*)"unionTCPFlags",                      1, 0 },
    { (char*)"silkTCPState",                       1, 0 },
    { (char*)"silkAppLabel",                       2, 0 },
    /* pad record to 64-bit boundary */
#if SKI_RWREC_PADDING != 0
    { (char*)"paddingOctets",  SKI_RWREC_PADDING, 0 },
#endif
    FB_IESPEC_NULL
};

/* Keep this in sync with the ski_rwrec_spec above. Pad to 64bits */
typedef struct ski_rwrec_st {
    uint64_t            flowStartMilliseconds;      /*   0-  7 */
    uint64_t            flowEndMilliseconds;        /*   8- 15 */

    uint8_t             sourceIPv6Address[16];      /*  16- 31 */
    uint8_t             destinationIPv6Address[16]; /*  32- 47 */

    uint32_t            sourceIPv4Address;          /*  48- 51 */
    uint32_t            destinationIPv4Address;     /*  52- 55 */

    uint16_t            sourceTransportPort;        /*  56- 57 */
    uint16_t            destinationTransportPort;   /*  58- 59 */

    uint32_t            ipNextHopIPv4Address;       /*  60- 63 */
    uint8_t             ipNextHopIPv6Address[16];   /*  64- 79 */
    uint32_t            ingressInterface;           /*  80- 83 */
    uint32_t            egressInterface;            /*  84- 87 */

    uint64_t            packetDeltaCount;           /*  88- 95 */
    uint64_t            octetDeltaCount;            /*  96-103 */

    uint8_t             protocolIdentifier;         /* 104     */
    sk_flowtype_id_t    silkFlowType;               /* 105     */
    sk_sensor_id_t      silkFlowSensor;             /* 106-107 */

    uint8_t             tcpControlBits;             /* 108     */
    uint8_t             initialTCPFlags;            /* 109     */
    uint8_t             unionTCPFlags;              /* 110     */
    uint8_t             silkTCPState;               /* 111     */
    uint16_t            silkAppLabel;               /* 112-113 */
#if SKI_RWREC_PADDING != 0
    uint8_t             pad[SKI_RWREC_PADDING];     /* 114-119 */
#endif
} ski_rwrec_t;



/* Bytes of padding to add to ski_extrwrec_spec and ski_extrwrec_st to
 * get a multiple of 64bits */
#define SKI_EXTRWREC_PADDING  3

/* These are additional IPFIX fields (or different encodings of the
 * SiLK fields) that we may get from other flowmeters.  They will be
 * appended to the ski_rwrec_spec (above) to create the complete
 * ski_extrwrec_t (defined below).  This has Template ID
 * SKI_EXTRWREC_TID. */
fbInfoElementSpec_t ski_extrwrec_spec[] = {
    /* Total counter support */
    { (char*)"packetTotalCount",                   8, 0 },
    { (char*)"octetTotalCount",                    8, 0 },
    { (char*)"initiatorPackets",                   8, 0 },
    { (char*)"initiatorOctets",                    8, 0 },
    /* Reverse counter support */
    { (char*)"reversePacketDeltaCount",            8, 0 },
    { (char*)"reverseOctetDeltaCount",             8, 0 },
    { (char*)"reversePacketTotalCount",            8, 0 },
    { (char*)"reverseOctetTotalCount",             8, 0 },
    { (char*)"responderPackets",                   8, 0 },
    { (char*)"responderOctets",                    8, 0 },
    /* Microsecond start and end (RFC1305-style) (extended time) */
    { (char*)"flowStartMicroseconds",              8, 0 },
    { (char*)"flowEndMicroseconds",                8, 0 },
    /* Nanosecond start and end (RFC1305-style) */
    { (char*)"flowStartNanoseconds",               8, 0 },
    { (char*)"flowEndNanoseconds",                 8, 0 },
    /* SysUpTime, used to handle Netflow v9 SysUpTime offset times */
    { (char*)"systemInitTimeMilliseconds",         8, 0 },
    /* Second start and end (extended time) */
    { (char*)"flowStartSeconds",                   4, 0 },
    { (char*)"flowEndSeconds",                     4, 0 },
    /* Flow durations (extended time) */
    { (char*)"flowDurationMicroseconds",           4, 0 },
    { (char*)"flowDurationMilliseconds",           4, 0 },
    /* Microsecond delta start and end (extended time) */
    { (char*)"flowStartDeltaMicroseconds",         4, 0 },
    { (char*)"flowEndDeltaMicroseconds",           4, 0 },
    /* Initial packet roundtrip */
    { (char*)"reverseFlowDeltaMilliseconds",       4, 0 },
    /* SysUpTime-based fields */
    { (char*)"flowStartSysUpTime",                 4, 0 },
    { (char*)"flowEndSysUpTime",                   4, 0 },
    /* Reverse flags */
    { (char*)"reverseTcpControlBits",              1, 0 },
    { (char*)"reverseInitialTCPFlags",             1, 0 },
    { (char*)"reverseUnionTCPFlags",               1, 0 },
    /* End reason */
    { (char*)"flowEndReason",                      1, 0 },
    /* Flow attributes */
    { (char*)"flowAttributes",                     2, 0 },
    { (char*)"reverseFlowAttributes",              2, 0 },
    /* Vlan IDs */
    { (char*)"vlanId",                             2, 0 },
    { (char*)"postVlanId",                         2, 0 },
    { (char*)"reverseVlanId",                      2, 0 },
    { (char*)"reversePostVlanId",                  2, 0 },
    /* ASN */
    { (char*)"bgpSourceAsNumber",                  4, 0 },
    { (char*)"bgpDestinationAsNumber",             4, 0 },
    /* MPLS */
    { (char*)"mplsTopLabelIPv4Address",            4, 0 },
    { (char*)"mplsTopLabelStackSection",           3, 0 },
    { (char*)"mplsLabelStackSection2",             3, 0 },
    { (char*)"mplsLabelStackSection3",             3, 0 },
    { (char*)"mplsLabelStackSection4",             3, 0 },
    { (char*)"mplsLabelStackSection5",             3, 0 },
    { (char*)"mplsLabelStackSection6",             3, 0 },
    { (char*)"mplsTopLabelPrefixLength",           1, 0 },
    { (char*)"mplsTopLabelType",                   1, 0 },
    /* Firewall events */
    { (char*)"firewallEvent",                      1, 0 },
    { (char*)"NF_F_FW_EVENT",                      1, 0 },
    { (char*)"NF_F_FW_EXT_EVENT",                  2, 0 },
    /* Collection time and Observation time */
    { (char*)"collectionTimeMilliseconds",         8, 0 },
    { (char*)"observationTimeMilliseconds",        8, 0 },
    { (char*)"observationTimeMicroseconds",        8, 0 },
    { (char*)"observationTimeNanoseconds",         8, 0 },
    { (char*)"observationTimeSeconds",             4, 0 },
    /* ICMP */
    { (char*)"icmpTypeCodeIPv4",                   2, 0 },
    { (char*)"icmpTypeCodeIPv6",                   2, 0 },
    { (char*)"icmpTypeIPv4",                       1, 0 },
    { (char*)"icmpCodeIPv4",                       1, 0 },
    { (char*)"icmpTypeIPv6",                       1, 0 },
    { (char*)"icmpCodeIPv6",                       1, 0 },
    /* flow direction */
    { (char*)"flowDirection",                      1, 0 },
    /* pad record to 64-bit boundary. */
#if SKI_EXTRWREC_PADDING != 0
    { (char*)"paddingOctets", SKI_EXTRWREC_PADDING, 0 },
#endif
    /* TOS */
    { (char*)"ipClassOfService",                   1, 0 },
    { (char*)"reverseIpClassOfService",            1, 0 },
    /* MAC Addresses */
    { (char*)"sourceMacAddress",                   6, 0 },
    { (char*)"destinationMacAddress",              6, 0 },
    /* Flow Sampler ID (IE48, name differs between fixbuf versions) */
    { (char*)"flowSamplerID",                      2, 1 }, /* current fixbuf */
    { (char*)"samplerId",                          2, 2 }, /* future fixbuf */

    { (char*)"subTemplateMultiList",               0, 0 },
    FB_IESPEC_NULL
};

/* Keep in sync with the ski_extrwrec_spec[] above. */
typedef struct ski_extrwrec_st {
    ski_rwrec_t     rw;                             /*   0-119 */

    uint64_t        packetTotalCount;               /* 120-127 */
    uint64_t        octetTotalCount;                /* 128-135 */
    uint64_t        initiatorPackets;               /* 136-143 */
    uint64_t        initiatorOctets;                /* 144-151 */

    uint64_t        reversePacketDeltaCount;        /* 152-159 */
    uint64_t        reverseOctetDeltaCount;         /* 160-167 */
    uint64_t        reversePacketTotalCount;        /* 168-175 */
    uint64_t        reverseOctetTotalCount;         /* 176-183 */
    uint64_t        responderPackets;               /* 184-191 */
    uint64_t        responderOctets;                /* 192-199 */

    /* Time can be represented in many different formats: */

    /* start time as NTP microseconds (RFC1305); may either have end
     * Time in same format or as an flowDurationMicroseconds value. */
    uint64_t        flowStartMicroseconds;          /* 200-207 */
    uint64_t        flowEndMicroseconds;            /* 208-215 */

    /* start time as NTP nanoseconds (RFC1305) */
    uint64_t        flowStartNanoseconds;           /* 216-223 */
    uint64_t        flowEndNanoseconds;             /* 224-231 */

    /* SysUpTime: used for flow{Start,End}SysUpTime calculations.
     * Needed to support Netflow v9 in particular. */
    uint64_t        systemInitTimeMilliseconds;     /* 232-239 */

    /* start time and end times as seconds since UNIX epoch. no
     * flowDuration field */
    uint32_t        flowStartSeconds;               /* 240-243 */
    uint32_t        flowEndSeconds;                 /* 244-247 */

    /* elapsed time as either microsec or millisec.  used when the
     * flowEnd time is not given. */
    uint32_t        flowDurationMicroseconds;       /* 248-251 */
    uint32_t        flowDurationMilliseconds;       /* 252-255 */

    /* start time as delta (negative microsec offsets) from the export
     * time; may either have end time in same format or a
     * flowDurationMicroseconds value */
    uint32_t        flowStartDeltaMicroseconds;     /* 256-259 */
    uint32_t        flowEndDeltaMicroseconds;       /* 260-263 */

    /* start time of reverse flow, as millisec offset from start time
     * of forward flow */
    uint32_t        reverseFlowDeltaMilliseconds;   /* 264-267 */

    /* Start and end time as delta from the system init time.  Needed
     * to support Netflow v9. */
    uint32_t        flowStartSysUpTime;             /* 268-271 */
    uint32_t        flowEndSysUpTime;               /* 272-275 */

    /* Flags for the reverse flow: */
    uint8_t         reverseTcpControlBits;          /* 276     */
    uint8_t         reverseInitialTCPFlags;         /* 277     */
    uint8_t         reverseUnionTCPFlags;           /* 278     */

    uint8_t         flowEndReason;                  /* 279     */

    /* Flow attribute flags */
    uint16_t        flowAttributes;                 /* 280-281 */
    uint16_t        reverseFlowAttributes;          /* 282-283 */

    /* vlan IDs */
    uint16_t        vlanId;                         /* 284-285 */
    uint16_t        postVlanId;                     /* 286-287 */
    uint16_t        reverseVlanId;                  /* 288-289 */
    uint16_t        reversePostVlanId;              /* 290-291 */

    /* ASN */
    uint32_t        bgpSourceAsNumber;              /* 292-295 */
    uint32_t        bgpDestinationAsNumber;         /* 296-299 */

    /* MPLS */
    uint32_t        mplsTopLabelIPv4Address;        /* 300-303 */
    uint8_t         mplsLabels[18];                 /* 304-321 */
    uint8_t         mplsTopLabelPrefixLength;       /* 322     */
    uint8_t         mplsTopLabelType;               /* 323     */

    /* Firewall events */
    uint8_t         firewallEvent;                  /* 324     */
    uint8_t         NF_F_FW_EVENT;                  /* 325     */
    uint16_t        NF_F_FW_EXT_EVENT;              /* 326-327 */

    /* Collection time and Observation time */
    uint64_t        collectionTimeMilliseconds;     /* 328-335 */
    uint64_t        observationTimeMilliseconds;    /* 336-343 */
    uint64_t        observationTimeMicroseconds;    /* 344-351 */
    uint64_t        observationTimeNanoseconds;     /* 352-359 */
    uint32_t        observationTimeSeconds;         /* 360-363 */

    /* ICMP */
    uint16_t        icmpTypeCodeIPv4;               /* 364-365 */
    uint16_t        icmpTypeCodeIPv6;               /* 366-367 */
    uint8_t         icmpTypeIPv4;                   /* 368 */
    uint8_t         icmpCodeIPv4;                   /* 369 */
    uint8_t         icmpTypeIPv6;                   /* 370 */
    uint8_t         icmpCodeIPv6;                   /* 371 */

    /* Flow Direction */
    uint8_t         flowDirection;                  /* 372 */

    /* padding */
#if SKI_EXTRWREC_PADDING != 0
    uint8_t         pad[SKI_EXTRWREC_PADDING];      /* 373-375 */
#endif

    /* TOS */
    uint8_t         ipClassOfService;               /* 376     */
    uint8_t         reverseIpClassOfService;        /* 377     */

    /* MAC Addresses */
    uint8_t         sourceMacAddress[6];            /* 378-383 */
    uint8_t         destinationMacAddress[6];       /* 384-389 */

    /* Flow Sampler ID */
    uint16_t        samplerId;                      /* 390-391 */

    /* TCP flags from yaf (when it is run without --silk) */
    fbSubTemplateMultiList_t stml;

} ski_extrwrec_t;

/* Support for reading TCP flags from an IPFIX subTemplateMultiList as
 * exported by YAF.  This has Template ID SKI_TCP_STML_TID.
 *
 * Keep this in sync with the ski_tcp_stml_t defined below. */
fbInfoElementSpec_t ski_tcp_stml_spec[] = {
    { (char*)"initialTCPFlags",                    1, 0 },
    { (char*)"unionTCPFlags",                      1, 0 },
    { (char*)"reverseInitialTCPFlags",             1, 0 },
    { (char*)"reverseUnionTCPFlags",               1, 0 },
    FB_IESPEC_NULL
};

/* Keep in sync with the ski_tcp_stml_spec[] defined above. */
typedef struct ski_tcp_stml_st {
    uint8_t         initialTCPFlags;
    uint8_t         unionTCPFlags;
    uint8_t         reverseInitialTCPFlags;
    uint8_t         reverseUnionTCPFlags;
} ski_tcp_stml_t;


/*
 *    Define the list of information elements and the corresponding
 *    struct for reading NetFlowV9 Options Template records that
 *    contains sampling information.  These records use internal
 *    template ID SKI_NF9_SAMPLING_TID.
 */
#define SKI_NF9_SAMPLING_PADDING 4
fbInfoElementSpec_t ski_nf9_sampling_spec[] = {
    { (char*)"samplingInterval",          4, 0 },    /* 34 */

    { (char*)"flowSamplerRandomInterval", 4, 1 },    /* 50, current fixbuf */
    { (char*)"samplerRandomInterval",     4, 2 },    /* 50, future fixbuf */

    { (char*)"samplingAlgorithm",         1, 0 },    /* 35 */

    { (char*)"flowSamplerMode",           1, 1 },    /* 49, current fixbuf */
    { (char*)"samplerMode",               1, 2 },    /* 49, future fixbuf */

    { (char*)"flowSamplerID",             2, 1 },    /* 48, current fixbuf */
    { (char*)"samplerId",                 2, 2 },    /* 48, future fixbuf */

#if SKI_NF9_SAMPLING_PADDING != 0
    { (char*)"paddingOctets",             SKI_NF9_SAMPLING_PADDING, 0 },
#endif
    FB_IESPEC_NULL
};

typedef struct ski_nf9_sampling_st {
    uint32_t    samplingInterval;
    uint32_t    samplerRandomInterval;
    uint8_t     samplingAlgorithm;
    uint8_t     samplerMode;
    uint16_t    samplerId;
#if SKI_NF9_SAMPLING_PADDING != 0
    uint8_t     paddingOctets[SKI_NF9_SAMPLING_PADDING];
#endif
} ski_nf9_sampling_t;


/* This lists statistics values that yaf may export. */
/* Keep this in sync with ski_yaf_stats_t defined in skipfix.h */
fbInfoElementSpec_t ski_yaf_stats_option_spec[] = {
    { (char*)"systemInitTimeMilliseconds",         8, 0 },
    { (char*)"exportedFlowRecordTotalCount",       8, 0 },
    { (char*)"packetTotalCount",                   8, 0 },
    { (char*)"droppedPacketTotalCount",            8, 0 },
    { (char*)"ignoredPacketTotalCount",            8, 0 },
    { (char*)"notSentPacketTotalCount",            8, 0 },
    { (char*)"expiredFragmentCount",               4, 0 },
#if 0
    { (char*)"assembledFragmentCount",             4, 0 },
    { (char*)"flowTableFlushEventCount",           4, 0 },
    { (char*)"flowTablePeakCount",                 4, 0 },
    { (char*)"meanFlowRate",                       4, 0 },
    { (char*)"meanPacketRate",                     4, 0 },
    { (char*)"exporterIPv4Address",                4, 0 },
#endif  /* 0 */
    { (char*)"exportingProcessId",                 4, 0 },
#if SKI_YAF_STATS_PADDING != 0
    { (char*)"paddingOctets", SKI_YAF_STATS_PADDING,  0 },
#endif
    FB_IESPEC_NULL
};

/* Values for the flowEndReason. this first set is defined by the
 * IPFIX spec */
#define SKI_END_IDLE            1
#define SKI_END_ACTIVE          2
#define SKI_END_CLOSED          3
#define SKI_END_FORCED          4
#define SKI_END_RESOURCE        5

/* SiLK will ignore flows with a flowEndReason of
 * SKI_END_YAF_INTERMEDIATE_FLOW */
#define SKI_END_YAF_INTERMEDIATE_FLOW 0x1F

/* Mask for the values of flowEndReason: want to ignore the next bit */
#define SKI_END_MASK            0x1f

/* Bits from flowEndReason: whether flow is a continuation */
#define SKI_END_ISCONT          0x80


/* Bits from flowAttributes */
#define SKI_FLOW_ATTRIBUTE_UNIFORM_PACKET_SIZE 0x01

/* A FIELD_IDENT is a 64-bit value that contains an IPFIX enterpriseId
 * in the upper 32 bits and an IPFIX elementId in the lower 32 */
#define FIELD_IDENT(fi_enterprise, fi_element)                  \
    ((((uint64_t)(fi_enterprise)) << 32) | (fi_element))

/*
 *    The global 'elem' variable is to increase processing speed.
 *
 *    The skiRwNextRecord() function takes different actions depending
 *    on whether the template (fbTemplate_t) for the record it is
 *    processing contains various information elements.
 *
 *    The template is examined by skiTemplateCallbackCtx() when it is
 *    initially received, reducing the overhead of examining the
 *    template for every record (at the expenses of looking for
 *    elements which skiRwNextRecord() may never actually need).
 *    Overall this should be a benefit as long as the number of
 *    records received is much higher than the number of templates
 *    received (in the TCP case, the templates are only sent once).
 *
 *    The 'elem' variable is the single instance of the 'elem_st'
 *    struct.  For each of the information elements of interest, the
 *    'elem' variable specifies a bit position.  (The 'elem' variable
 *    provides a sort of enumeration.)
 *
 *    The TEMPLATE_SET_BIT() macro sets one bit on a bitmap.  The
 *    macro takes the bitmap and the member of the 'elem_st'
 *    structure whose bit position is to be set.
 *
 *    The TEMPLATE_GET_BIT() macro checks whether a bit is set on a
 *    bitmap.  It takes the bitmap and the member of the 'elem_st'
 *    structure whose bit position you want to examine.
 */
const struct elem_st {
    /* either sourceIPv4Address or destinationIPv4Address */
    uint8_t     sourceIPv4Address;

    /* either sourceIPv6Address or destinationIPv6Address */
    uint8_t     sourceIPv6Address;

    uint8_t     NF_F_FW_EVENT;
    uint8_t     NF_F_FW_EXT_EVENT;
    uint8_t     collectionTimeMilliseconds;
    uint8_t     exportTimeSeconds;
    uint8_t     firewallEvent;
    uint8_t     flowDurationMicroseconds;
    uint8_t     flowDurationMilliseconds;
    uint8_t     flowEndDeltaMicroseconds;
    uint8_t     flowEndMicroseconds;
    uint8_t     flowEndMilliseconds;
    uint8_t     flowEndNanoseconds;
    uint8_t     flowEndSeconds;
    uint8_t     flowStartDeltaMicroseconds;
    uint8_t     flowStartMicroseconds;
    uint8_t     flowStartMilliseconds;
    uint8_t     flowStartNanoseconds;
    uint8_t     flowStartSeconds;
    uint8_t     flowStartSysUpTime;
    uint8_t     icmpTypeCodeIPv4;
    uint8_t     icmpTypeIPv4;
    uint8_t     mplsTopLabelStackSection;
    uint8_t     observationTimeMicroseconds;
    uint8_t     observationTimeMilliseconds;
    uint8_t     observationTimeNanoseconds;
    uint8_t     observationTimeSeconds;
    uint8_t     postVlanId;
    uint8_t     reverseInitialTCPFlags;
    uint8_t     reverseTcpControlBits;
    uint8_t     reverseVlanId;
    uint8_t     systemInitTimeMilliseconds;

    /* both IE49,IE50 (samplerMode, samplerRandomInterval) are present */
    uint8_t     samplerMode;

    /* both IE35,IE34 (samplingAlgorithm, samplingInterval) are present */
    uint8_t     samplingAlgorithm;
} elem = {
    1,      /*  sourceIPv4Address or destinationIPv4Address */
    2,      /*  sourceIPv6Address or destinationIPv6Address */

    3,      /*  NF_F_FW_EVENT */
    4,      /*  NF_F_FW_EXT_EVENT */
    5,      /*  collectionTimeMilliseconds */
    6,      /*  exportTimeSeconds */
    7,      /*  firewallEvent */
    8,      /*  flowDurationMicroseconds */
    9,      /*  flowDurationMilliseconds */
    10,     /*  flowEndDeltaMicroseconds */
    11,     /*  flowEndMicroseconds */
    12,     /*  flowEndMilliseconds */
    13,     /*  flowEndNanoseconds */
    14,     /*  flowEndSeconds */
    15,     /*  flowStartDeltaMicroseconds */
    16,     /*  flowStartMicroseconds */
    17,     /*  flowStartMilliseconds */
    18,     /*  flowStartNanoseconds */
    19,     /*  flowStartSeconds */
    20,     /*  flowStartSysUpTime */
    21,     /*  icmpTypeCodeIPv4, icmpTypeCodeIPv6 */
    22,     /*  icmpTypeIPv4, icmpCodeIPv4, icmpTypeIPv6, icmpCodeIPv6 */
    23,     /*  mplsTopLabelStackSection */
    24,     /*  observationTimeMicroseconds */
    25,     /*  observationTimeMilliseconds */
    26,     /*  observationTimeNanoseconds */
    27,     /*  observationTimeSeconds */
    28,     /*  postVlanId */
    29,     /*  reverseInitialTCPFlags */
    30,     /*  reverseTcpControlBits */
    31,     /*  reverseVlanId */
    32,     /*  systemInitTimeMilliseconds */

    /* The following are only seen in options templates, so the bit
     * position here can repeat those above */

    1,      /*  samplerMode and samplerRandomInterval */
    2       /*  samplingAlgorithm and samplingInterval */
};

#define TEMPLATE_SET_BIT(tsb_bitmap, tsb_member)        \
    tsb_bitmap |= (1 << (elem. tsb_member ))

#define TEMPLATE_GET_BIT(tgb_bitmap, tgb_member)        \
    ((tgb_bitmap) & (1 << elem. tgb_member ))

#define ASSERT_IE_NAME_IS(aini_ie, aini_name)                           \
    assert(elem. aini_name                                              \
           && 0==strcmp((aini_ie)->ref.canon->ref.name, #aini_name))

#if SKIPFIX_ALLOCATE_BITMAP
#  define TYPEOF_BITMAP  uint64_t
#  define GET_BITMAP_FROM_TEMPLATE(gbft_template)       \
    *((uint64_t*)fbTemplateGetContext(gbft_template))
#else
#  define TYPEOF_BITMAP  uintptr_t
#  define GET_BITMAP_FROM_TEMPLATE(gbft_template)       \
    (uintptr_t)fbTemplateGetContext(gbft_template)
#endif

/*
 *    There is a single infomation model.
 */
static fbInfoModel_t *ski_model = NULL;

/*
 *    When processing files with fixbuf, the session object
 *    (fbSession_t) is owned the reader/write buffer (fBuf_t).
 *
 *    When doing network processing, the fBuf_t does not own the
 *    session.  We use this global vector to maintain those session
 *    pointers so they can be freed at shutdown.
 */
static sk_vector_t *session_list = NULL;

/*
 *    If non-zero, print the templates when they arrive.  This can be
 *    set by defining the environment variable specified in
 *    SKI_ENV_PRINT_TEMPLATES.
 */
static int print_templates = 0;

/*
 *    The names of IE 48, 49, 50 used by fixbuf (flowSamplerFOO) do
 *    not match the names specified by IANA (samplerFOO).  At some
 *    point the names used by fixbuf will change, and this variable is
 *    for forward compatibility to determine which names fixbuf uses.
 *    It is set by skiInitialize().
 *
 *    Variables and structure members in this file use the IANA name.
 */
static uint32_t sampler_flags = 0;


