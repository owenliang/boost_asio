#COMAKE2 edit-mode: -*- Makefile -*-
####################64Bit Mode####################
ifeq ($(shell uname -m),x86_64)
CC=gcc
CXX=g++
CXXFLAGS=-g \
  -pipe \
  -W \
  -Wall \
  -fPIC \
  -DBOOST_ASIO_HAS_EPOLL=1
CFLAGS=-g \
  -pipe \
  -W \
  -Wall \
  -fPIC
CPPFLAGS=
INCPATH=-I. \
  -I./include \
  -I./output \
  -I./output/include
DEP_INCPATH=-I../../third-64/boost \
  -I../../third-64/boost/include \
  -I../../third-64/boost/output \
  -I../../third-64/boost/output/include \
  -I../../third-64/tcmalloc \
  -I../../third-64/tcmalloc/include \
  -I../../third-64/tcmalloc/output \
  -I../../third-64/tcmalloc/output/include

#============ CCP vars ============
CCHECK=@ccheck.py
CCHECK_FLAGS=
PCLINT=@pclint
PCLINT_FLAGS=
CCP=@ccp.py
CCP_FLAGS=


#COMAKE UUID
COMAKE_MD5=3acc32839a2f2c6f85107141e2137002  COMAKE


.PHONY:all
all:comake2_makefile_check echo-sample output-bin 
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mall[0m']"
	@echo "make all done"

.PHONY:comake2_makefile_check
comake2_makefile_check:
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mcomake2_makefile_check[0m']"
	#in case of error, update 'Makefile' by 'comake2'
	@echo "$(COMAKE_MD5)">comake2.md5
	@md5sum -c --status comake2.md5
	@rm -f comake2.md5

.PHONY:ccpclean
ccpclean:
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mccpclean[0m']"
	@echo "make ccpclean done"

.PHONY:clean
clean:ccpclean
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mclean[0m']"
	rm -rf echo-sample
	rm -rf ./output/bin/echo-sample
	rm -rf output-bin
	rm -rf output;
	rm -rf echo-sample_echo_server.o

.PHONY:dist
dist:
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mdist[0m']"
	tar czvf output.tar.gz output
	@echo "make dist done"

.PHONY:distclean
distclean:clean
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mdistclean[0m']"
	rm -f output.tar.gz
	@echo "make distclean done"

.PHONY:love
love:
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mlove[0m']"
	@echo "make love done"

echo-sample:echo-sample_echo_server.o
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mecho-sample[0m']"
	$(CXX) echo-sample_echo_server.o -Xlinker "-("  ../../third-64/boost/lib/libboost_atomic.a \
  ../../third-64/boost/lib/libboost_chrono.a \
  ../../third-64/boost/lib/libboost_container.a \
  ../../third-64/boost/lib/libboost_context.a \
  ../../third-64/boost/lib/libboost_coroutine.a \
  ../../third-64/boost/lib/libboost_date_time.a \
  ../../third-64/boost/lib/libboost_exception.a \
  ../../third-64/boost/lib/libboost_filesystem.a \
  ../../third-64/boost/lib/libboost_graph.a \
  ../../third-64/boost/lib/libboost_locale.a \
  ../../third-64/boost/lib/libboost_log_setup.a \
  ../../third-64/boost/lib/libboost_math_c99.a \
  ../../third-64/boost/lib/libboost_math_c99f.a \
  ../../third-64/boost/lib/libboost_math_c99l.a \
  ../../third-64/boost/lib/libboost_math_tr1.a \
  ../../third-64/boost/lib/libboost_math_tr1f.a \
  ../../third-64/boost/lib/libboost_math_tr1l.a \
  ../../third-64/boost/lib/libboost_prg_exec_monitor.a \
  ../../third-64/boost/lib/libboost_program_options.a \
  ../../third-64/boost/lib/libboost_python.a \
  ../../third-64/boost/lib/libboost_random.a \
  ../../third-64/boost/lib/libboost_regex.a \
  ../../third-64/boost/lib/libboost_serialization.a \
  ../../third-64/boost/lib/libboost_signals.a \
  ../../third-64/boost/lib/libboost_system.a \
  ../../third-64/boost/lib/libboost_test_exec_monitor.a \
  ../../third-64/boost/lib/libboost_thread.a \
  ../../third-64/boost/lib/libboost_timer.a \
  ../../third-64/boost/lib/libboost_unit_test_framework.a \
  ../../third-64/boost/lib/libboost_wave.a \
  ../../third-64/boost/lib/libboost_wserialization.a \
  ../../third-64/tcmalloc/lib/libprofiler.a \
  ../../third-64/tcmalloc/lib/libtcmalloc.a \
  ../../third-64/tcmalloc/lib/libtcmalloc_and_profiler.a \
  ../../third-64/tcmalloc/lib/libtcmalloc_debug.a \
  ../../third-64/tcmalloc/lib/libtcmalloc_minimal.a \
  ../../third-64/tcmalloc/lib/libtcmalloc_minimal_debug.a -lpthread \
  -lcrypto \
  -lrt -Xlinker "-)" -o echo-sample
	mkdir -p ./output/bin
	cp -f --link echo-sample ./output/bin

output-bin:
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40moutput-bin[0m']"
	echo "build output-bin over"

echo-sample_echo_server.o:echo_server.cc
	@echo "[[1;32;40mCOMAKE:BUILD[0m][Target:'[1;32;40mecho-sample_echo_server.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o echo-sample_echo_server.o echo_server.cc

endif #ifeq ($(shell uname -m),x86_64)


