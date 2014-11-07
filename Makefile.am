APXS = @APXS@

noinst_PROGRAMS = mod_reslog

mod_reslog$(EXEEXT): mod_reslog.c
	$(APXS) -Wc,-g -L$(srcdir) -c mod_reslog.c
	rm -f mod_reslog.so
	ln -s .libs/mod_reslog.so .

install-exec-hook:
	$(APXS) -i -a mod_reslog.so

clean-local:
	rm -rvf *.{so,slo,la,lo}

distclean-local:
	rm -rvf config.log config.status .deps .libs *-stamp config.h stamp-*

