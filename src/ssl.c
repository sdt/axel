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

/*
 *  TODO: this stuff should not be global
 *
 *  Need to figure out what is truly global (eg loading the certificates),
 *  what is per-connection.
 */
static int done_startup = 0;
static conf_t *conf = NULL;
static gnutls_certificate_credentials_t xcred;
static int cert_verify_cb( gnutls_session_t session );

void ssl_init( conf_t *global_conf )
{
	conf = global_conf;
}

void ssl_startup( void )
{
	int ret;

	if( done_startup )
		return;

	gnutls_global_init();
	gnutls_certificate_allocate_credentials( &xcred );
	ret = gnutls_certificate_set_x509_system_trust( xcred );
	printf("ret = %d (%s)\n", ret, gnutls_strerror(ret));

	done_startup = 1;
}

int ssl_connect( tcp_t *tcp, char *hostname, char *message )
{
	int ret = -1;
	int type;
	gnutls_datum_t out;
	gnutls_session_t *session = &tcp->ssl.session;

	ssl_startup();
	gnutls_init( session, GNUTLS_CLIENT );
	gnutls_session_set_ptr( *session, tcp );
	gnutls_server_name_set( *session, GNUTLS_NAME_DNS,
				hostname, strlen( hostname ) );
	gnutls_set_default_priority( *session );
	gnutls_credentials_set( *session, GNUTLS_CRD_CERTIFICATE, xcred );
	gnutls_transport_set_int( *session, tcp->fd );
	gnutls_handshake_set_timeout( *session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT );

	if( !conf->insecure ) {
		/* Beware: hostname needs to stick around for the lifetime
		 * of the connection. This is true right now as it lives in
		 * the conn_t structure, but that may change in future.
		 */
		tcp->ssl.hostinfo.type = GNUTLS_DT_DNS_HOSTNAME;
		tcp->ssl.hostinfo.data = (void*) hostname;
		tcp->ssl.hostinfo.size = 0;
		gnutls_session_set_verify_function( *session, cert_verify_cb );
	}

	while ( ( ret = gnutls_handshake( *session ) ) < 0 ) {

		if( gnutls_error_is_fatal( ret ) ) {
			fprintf(stderr, "*** Handshake failed: %d\n", ret);
			gnutls_perror( ret );
			close( tcp->fd );
			tcp->fd = -1;
			gnutls_deinit( *session );
			return 0;
		}
	}

        /* check certificate verification status */
	if( !conf->insecure ) {
		type = gnutls_certificate_type_get( *session );
		ret = gnutls_certificate_verification_status_print(
			tcp->ssl.status, type, &out, 0);
		if( ret < 0 ) {
			printf( "Error\n" );
			return GNUTLS_E_CERTIFICATE_ERROR;
		}

		printf( "OUT: %s\n", out.data );
		gnutls_free( out.data );
	}

	return 1;
}

int ssl_read( tcp_t *tcp, void *buf, int bytes )
{
	return gnutls_record_recv( tcp->ssl.session, buf, bytes );
}

int ssl_write( tcp_t *tcp, void *buf, int bytes )
{
	return gnutls_record_send( tcp->ssl.session, buf, bytes );
}

void ssl_disconnect( tcp_t *tcp )
{
	gnutls_bye( tcp->ssl.session, GNUTLS_SHUT_RDWR );
	close( tcp->fd );
	tcp->fd = -1;
	gnutls_deinit( tcp->ssl.session );
}

static int cert_verify_cb( gnutls_session_t session )
{
	tcp_t *tcp;
	int ret;

	tcp = gnutls_session_get_ptr( session );
	ret = gnutls_certificate_verify_peers(
		session, &tcp->ssl.hostinfo, 1, &tcp->ssl.status);

	if( ret < 0 ) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	if( tcp->ssl.status != 0) { /* Certificate is not trusted */
		return GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR;
	}
	/* notify gnutls to continue handshake normally */
	return 0;
}
