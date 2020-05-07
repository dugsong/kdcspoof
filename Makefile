#
# Makefile for kdcspoof
#
# Dug Song <dugsong@monkey.org>

CC	= gcc
CFLAGS	= -Wall -O2 `libnet-config --defines`

KRB4DIR = /usr
KRB4INC = -I$(KRB4DIR)/include/kerberosIV
KRB4LIB = -I$(KRB4DIR)/lib -lkrb -ldes

KRB5DIR	= /usr/local/heimdal
KRB5INC	= -I$(KRB5DIR)/include
KRB5LIB	= -L$(KRB5DIR)/lib -lkrb5 -ldes -lasn1 -lroken

LNETDIR	= /usr/local
LNETINC	= -I$(LNETDIR)/include
LNETLIB	= -L$(LNETDIR)/lib -lnet

PCAPDIR = /usr
PCAPINC	= -I$(PCAPDIR)/include
PCAPLIB = -L$(PCAPDIR)/lib -lpcap

INCS	= $(KRB4INC) $(KRB5INC) $(LNETINC) $(PCAPINC)
LIBS	= $(KRB4LIB) $(KRB5LIB) $(LNETLIB) $(PCAPLIB)

all: kdcspoof

kdcspoof: kdcspoof.c
	$(CC) $(CFLAGS) $(INCS) -o $@ kdcspoof.c $(LIBS)

clean:
	rm -f kdcspoof *.o *~

