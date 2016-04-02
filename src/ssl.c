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

static int done_startup = 0;
static conf_t *conf = NULL;
static gnutls_certificate_credentials_t xcred;

void ssl_init( conf_t *global_conf )
{
	conf = global_conf;
}

void ssl_startup( void )
{
	if( done_startup )
		return;

	gnutls_global_init();
	gnutls_certificate_allocate_credentials( &xcred );
	gnutls_certificate_set_x509_trust_file( xcred, "pcks11:",
		GNUTLS_X509_FMT_PEM );

/*
	ssl_ctx = SSL_CTX_new( SSLv23_client_method() );
	if( !conf->insecure ) {
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_ctx, 0);
	}
*/

	done_startup = 1;
}

int ssl_connect( tcp_t *tcp, char *hostname, char *message )
{
	int ret;

	ssl_startup();
	gnutls_init( &tcp->ssl, GNUTLS_CLIENT );
	gnutls_set_default_priority( tcp->ssl );
	gnutls_credentials_set( tcp->ssl, GNUTLS_CRD_CERTIFICATE, xcred );
	gnutls_transport_set_int( tcp->ssl, tcp->fd );
	gnutls_handshake_set_timeout( tcp->ssl, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT );

	for( ; ; ) {
		ret = gnutls_handshake( tcp->ssl );

		if( ret >= 0 ) {
			return 1;
		}

		if( gnutls_error_is_fatal( ret ) ) {
			fprintf(stderr, "*** Handshake failed\n");
			gnutls_perror( ret );
			close( tcp->fd );
			tcp->fd = -1;
			gnutls_deinit( tcp->ssl );
			return 0;
		}
	}
}

int ssl_read( tcp_t *tcp, void *buf, int bytes )
{
	return gnutls_record_recv( tcp->ssl, buf, bytes );
}

int ssl_write( tcp_t *tcp, void *buf, int bytes )
{
	return gnutls_record_send( tcp->ssl, buf, bytes );
}

void ssl_disconnect( tcp_t *tcp )
{
	gnutls_bye( tcp->ssl, GNUTLS_SHUT_RDWR );
	close( tcp->fd );
	tcp->fd = -1;
	gnutls_deinit( tcp->ssl );
}
