ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libwolfspdm.la

libwolfspdm_la_SOURCES = \
    src/spdm_context.c \
    src/spdm_crypto.c \
    src/spdm_kdf.c \
    src/spdm_msg.c \
    src/spdm_secured.c \
    src/spdm_session.c \
    src/spdm_transcript.c

if BUILD_CERT
libwolfspdm_la_SOURCES += src/spdm_standard.c
endif
if BUILD_TCG
libwolfspdm_la_SOURCES += src/spdm_tcg.c
endif
if BUILD_PSK
libwolfspdm_la_SOURCES += src/spdm_psk.c
endif
if BUILD_NUVOTON
libwolfspdm_la_SOURCES += src/vendor/spdm_nuvoton.c
endif
if BUILD_NATIONS
libwolfspdm_la_SOURCES += src/vendor/spdm_nations.c
endif
if BUILD_RESPONDER
libwolfspdm_la_SOURCES += src/spdm_responder.c
endif

libwolfspdm_la_CPPFLAGS = -I$(srcdir)/wolfspdm -I$(srcdir)/src
libwolfspdm_la_LIBADD = -lwolfssl

# Generate options.h from config.h (propagate WOLFSPDM_ defines to consumers)
BUILT_SOURCES = wolfspdm/options.h
wolfspdm/options.h: config.h
	@mkdir -p wolfspdm
	@echo '/* wolfspdm/options.h - auto-generated from config.h, do not edit */' > $@
	@echo '#ifndef WOLFSPDM_OPTIONS_H' >> $@
	@echo '#define WOLFSPDM_OPTIONS_H' >> $@
	@grep '^\#define WOLFSPDM_' config.h >> $@ || true
	@echo '#endif /* WOLFSPDM_OPTIONS_H */' >> $@

# Public headers
nobase_include_HEADERS = \
    wolfspdm/spdm.h \
    wolfspdm/spdm_types.h \
    wolfspdm/spdm_error.h \
    wolfspdm/spdm_tcg.h \
    wolfspdm/spdm_psk.h \
    wolfspdm/spdm_nuvoton.h \
    wolfspdm/spdm_nations.h \
    wolfspdm/spdm_responder.h \
    wolfspdm/options.h

# Test programs
check_PROGRAMS = test/unit_test

test_unit_test_SOURCES = test/unit_test.c test/test_certs.h
test_unit_test_CPPFLAGS = -I$(srcdir)/wolfspdm -I$(srcdir)/src
test_unit_test_LDADD = libwolfspdm.la -lwolfssl

TESTS = test/unit_test

# spdm-emu driver (standard certificate flow over TCP/MCTP)
if BUILD_CERT
noinst_PROGRAMS = examples/spdm_demo
examples_spdm_demo_SOURCES = examples/spdm_demo.c
examples_spdm_demo_CPPFLAGS = -I$(srcdir)/wolfspdm
examples_spdm_demo_LDADD = libwolfspdm.la -lwolfssl
endif

# pkgconfig
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = wolfspdm.pc

EXTRA_DIST = \
    src/spdm_internal.h \
    examples/spdm_test.sh \
    autogen.sh \
    README.md \
    LICENSE \
    wolfspdm.pc.in

CLEANFILES = wolfspdm.pc wolfspdm/options.h
