/*
  Axel -- A lighter download accelerator for Linux and other Unices

  Copyright 2001-2007 Wilmer van der Gaast
  Copyright 2007-2009 Y Giridhar Appaji Nag
  Copyright 2008-2009 Philipp Hagemeister
  Copyright 2015-2016 Joao Eriberto Mota Filho
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

typedef SSL ssl_t;    /* OpenSSL implementation */

void ssl_init( conf_t *conf );
ssl_t* ssl_connect( int fd, char *message );
int ssl_read( ssl_t *ssl, void *buf, int bytes );
int ssl_write( ssl_t *ssl, void *buf, int bytes );
void ssl_disconnect( ssl_t *ssl );
