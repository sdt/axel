/*
  Axel -- A lighter download accelerator for Linux and other Unices

  Copyright 2001-2007 Wilmer van der Gaast
  Copyright 2008      Y Giridhar Appaji Nag
  Copyright 2008-2009 Philipp Hagemeister
  Copyright 2015      Joao Eriberto Mota Filho
  Copyright 2016      Ivan Gimenez

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* SSL interface */

#include "axel.h"

static conf_t *conf = NULL;

void ssl_init( conf_t *global_conf )
{
	conf = global_conf;
}

void ssl_startup( void )
{
/*
	if( ssl_ctx != NULL )
		return;

	SSL_library_init();
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new( SSLv23_client_method() );
	if( !conf->insecure ) {
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_ctx, 0);
	}
*/
}

int ssl_connect( ssl_t *ssl, int fd, char *hostname, char *message )
{
/*
	ssl_startup();

	ssl = SSL_new( ssl_ctx );
	SSL_set_fd( ssl, fd );

	int err = SSL_connect( ssl );
	if( err <= 0 ) {
		sprintf(message, _("SSL error: %s\n"), ERR_reason_error_string(ERR_get_error()));
		return NULL;
	}
*/

	return 0;
}

int ssl_read( ssl_t *ssl, void *buf, int bytes )
{
    return 0;
}

int ssl_write( ssl_t *ssl, void *buf, int bytes )
{
	return 0;
}

void ssl_disconnect( ssl_t *ssl )
{
/*
	SSL_shutdown( ssl );
	SSL_free( ssl );
*/
}

// https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/sect-Defensive_Coding-TLS-Client-NSS.html

// NSPR include files
#include <prerror.h>
#include <prinit.h>

// NSS include files
#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nss/secmod.h>
#include <nss/ssl.h>
#include <nss/sslproto.h>

// Private API, no other way to turn a POSIX file descriptor into an
// NSPR handle.
NSPR_API(PRFileDesc*) PR_ImportTCPSocket(int);

void ssl_startup2 ( void )
{
	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
	NSSInitContext *const ctx =
	NSS_InitContext("sql:/etc/pki/nssdb", "", "", "", NULL,
			NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
	if (ctx == NULL) {
	const PRErrorCode err = PR_GetError();
	fprintf(stderr, "error: NSPR error code %d: %s\n",
		err, PR_ErrorToName(err));
	exit(1);
	}

	// Ciphers to enable.
	static const PRUint16 good_ciphers[] = {
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	SSL_NULL_WITH_NULL_NULL // sentinel
	};

	// Check if the current policy allows any strong ciphers.  If it
	// doesn't, set the cipher suite policy.  This is not thread-safe
	// and has global impact.  Consequently, we only do it if absolutely
	// necessary.
	int found_good_cipher = 0;
	for (const PRUint16 *p = good_ciphers; *p != SSL_NULL_WITH_NULL_NULL;
	++p) {
	PRInt32 policy;
	if (SSL_CipherPolicyGet(*p, &policy) != SECSuccess) {
	const PRErrorCode err = PR_GetError();
	fprintf(stderr, "error: policy for cipher %u: error %d: %s\n",
		(unsigned)*p, err, PR_ErrorToName(err));
	exit(1);
	}
	if (policy == SSL_ALLOWED) {
	fprintf(stderr, "info: found cipher %x\n", (unsigned)*p);
	found_good_cipher = 1;
	break;
	}
	}
	if (!found_good_cipher) {
	if (NSS_SetDomesticPolicy() != SECSuccess) {
	const PRErrorCode err = PR_GetError();
	fprintf(stderr, "error: NSS_SetDomesticPolicy: error %d: %s\n",
		err, PR_ErrorToName(err));
	exit(1);
	}
	}

	// Initialize the trusted certificate store.
	char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
	SECMODModule *module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);
	if (module == NULL || !module->loaded) {
	const PRErrorCode err = PR_GetError();
	fprintf(stderr, "error: NSPR error code %d: %s\n",
		err, PR_ErrorToName(err));
	exit(1);
	}

int sockfd = 1;
const char *host = "google.com";

// Wrap the POSIX file descriptor.  This is an internal NSPR
// function, but it is very unlikely to change.
PRFileDesc* nspr = PR_ImportTCPSocket(sockfd);
sockfd = -1; // Has been taken over by NSPR.

// Add the SSL layer.
{
  PRFileDesc *model = PR_NewTCPSocket();
  PRFileDesc *newfd = SSL_ImportFD(NULL, model);
  if (newfd == NULL) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: NSPR error code %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  model = newfd;
  newfd = NULL;
  if (SSL_OptionSet(model, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_ENABLE_SSL2 error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_OptionSet(model, SSL_V2_COMPATIBLE_HELLO, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_V2_COMPATIBLE_HELLO error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_OptionSet(model, SSL_ENABLE_DEFLATE, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_ENABLE_DEFLATE error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }

  // Allow overriding invalid certificate.
  if (SSL_BadCertHook(model, NULL, (char *)host) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: SSL_BadCertHook error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }

  newfd = SSL_ImportFD(model, nspr);
  if (newfd == NULL) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  nspr = newfd;
  PR_Close(model);
}

// Perform the handshake.
if (SSL_ResetHandshake(nspr, PR_FALSE) != SECSuccess) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
if (SSL_SetURL(nspr, host) != SECSuccess) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
if (SSL_ForceHandshake(nspr) != SECSuccess) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
char buf[4096];
snprintf(buf, sizeof(buf), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
PRInt32 ret = PR_Write(nspr, buf, strlen(buf));
if (ret < 0) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: PR_Write error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
ret = PR_Read(nspr, buf, sizeof(buf));
if (ret < 0) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: PR_Read error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
// Send close_notify alert.
if (PR_Shutdown(nspr, PR_SHUTDOWN_BOTH) != PR_SUCCESS) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: PR_Read error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
// Closes the underlying POSIX file descriptor, too.
PR_Close(nspr);
}
