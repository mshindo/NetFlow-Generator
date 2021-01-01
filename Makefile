#
# Copyright (c) 2004-2021  by Motonori Shindo <motonori@shin.do>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
mandir = ${prefix}/share/man
srcdir = .

CC = gcc
PROG = flowgen
CCOPT = -Wall
INCLS =
DEFS =

# Standard CFLAGS
CFLAGS = $(CCOPT) $(DEFS) $(INCLS)

# Standard LDFLAGS
LDFLAGS =
# Standard LIBS
LIBS =

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

SRC = flowgen.c
OBJ = $(SRC:.c=.o)
HDR = netflow.h

all: $(PROG)

$(PROG): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

$(OBJ): $(HDR)

install:
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(bindir)/$(PROG)
	$(INSTALL_DATA) $(srcdir)/$(PROG).1 $(DESTDIR)$(mandir)/man1/$(PROG).1

uninstall:
	rm -f $(DESTDIR)$(bindir)/$(PROG)
	rm -f $(DESTDIR)$(mandir)/man1/$(PROG).1

clean:
	rm -f $(PROG) $(OBJ) *~
