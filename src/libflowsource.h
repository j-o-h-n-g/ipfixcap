/*
** Copyright (C) 2004-2016 by Carnegie Mellon University.
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
**  libflowsource.h
**
**    Definitions/Declaration for the libflowsource library and all
**    the possible external flow sources (IPFIX, PDU, etc).
**
*/


/***  IPFIX SOURCES  ******************************************************/


/**
 *    Values that represent constants used by the IPFIX standard
 *    and/or CISCO devices to represent firewall events:
 *
 *      firewallEvent is an official IPFIX information element, IE 233
 *
 *      NF_F_FW_EVENT is Cisco IE 40005
 *
 *      NF_F_FW_EXT_EVENT is Cisco IE 33002.
 *
 *    The NF_F_FW_EXT_EVENT provides a subtype for the NF_F_FW_EVENT
 *    type.  See the lengthy comment in skipfix.c.
 */
#define SKIPFIX_FW_EVENT_CREATED            1
#define SKIPFIX_FW_EVENT_DELETED            2
#define SKIPFIX_FW_EVENT_DENIED             3
/* denied due to ingress acl */
#define SKIPFIX_FW_EVENT_DENIED_INGRESS       1001
/* denied due to egress acl */
#define SKIPFIX_FW_EVENT_DENIED_EGRESS        1002
/* denied due to attempting to contact ASA's service port */
#define SKIPFIX_FW_EVENT_DENIED_SERV_PORT     1003
/* denied due to first packet not syn */
#define SKIPFIX_FW_EVENT_DENIED_NOT_SYN       1004
#define SKIPFIX_FW_EVENT_ALERT              4
#define SKIPFIX_FW_EVENT_UPDATED            5

/**
 *    Return true if value in 'sfedcv_val' is recognized as a
 *    NF_F_FW_EXT_EVENT sub-value for "Denied" firewall events.
 */
#define SKIPFIX_FW_EVENT_DENIED_CHECK_VALID(sfedcv_val)         \
    (SKIPFIX_FW_EVENT_DENIED_INGRESS <= (sfedcv_val)            \
     && SKIPFIX_FW_EVENT_DENIED_NOT_SYN >= (sfedcv_val))


/**
 *    An IPFIX source is a flow record source based on IPFIX or
 *    NetFlow V9 records.  Once created, records can be requested of
 *    it via a pull mechanism.
 */
typedef struct skIPFIXSource_st skIPFIXSource_t;


/**
 *    Record type returned by skIPFIXSource_t.
 */
typedef rwGenericRec_V5 skIPFIXSourceRecord_t;


/**
 *    Get a pointer to a SiLK Flow record given a pointer to an
 *    skIPFIXSourceRecord_t.
 */
#define skIPFIXSourceRecordGetRwrec(ipfix_src_rec)      \
    ((rwRec*)(ipfix_src_rec))

