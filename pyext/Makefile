PYTHON?=$(shell which python)

XED_ROOT?=$(CURDIR)/../build/xedkit
XED_INCLUDE?=${XED_ROOT}/include
XED_LIB?=${XED_ROOT}/lib/

LIBUNWIND_ROOT?=$(CURDIR)/../build/libunwindkit
LIBUNWIND_INCLUDE?=${LIBUNWIND_ROOT}/include
LIBUNWIND_LIB?=${LIBUNWIND_ROOT}/lib
LIBUNWIND_NEEDS_LZMA=$(shell find ${LIBUNWIND_ROOT} -name libunwind.a | xargs nm | grep lzma >/dev/null && echo '-llzma')

SAFESTRINGLIB_ROOT?=$(CURDIR)/../3rd_party/safestringlib
SAFESTRINGLIB_INCLUDE?=${SAFESTRINGLIB_ROOT}/include
SAFESTRINGLIB_LIBRARY?=${SAFESTRINGLIB_ROOT}/libsafestring.a

PROTOBUF_KIT=$(CURDIR)/../build/protobuf-ckit

LIBPROBENGINE_DIR?=$(CURDIR)/../libprobengine
LIBPROBENGINE=$(LIBPROBENGINE_DIR)/build
LIBPROBENGINE_LIB=$(LIBPROBENGINE)/libpysamprof-probengine.a

COMMON_DIR=$(CURDIR)/../common
COMMON_MAKEFILE=$(COMMON_DIR)/Makefile
COMMON_LIBRARY=$(COMMON_DIR)/build/libpysamprof-common.a

GET_PYCONFIG?=$(shell which python-config)

C_SOURCE_PATH?=$(CURDIR)
C_INCLUDE_PATH?=$(CURDIR)
OBJECTS_PATH?=build/obj
GEN_HEADERS_PATH?=build/headers
TARGET_PATH?=$(CURDIR)/build
TARGET_NAME:=pysamprof.so

IPCNG_DIR=$(CURDIR)/../libipc-ng
IPCNG_MAKEFILE=$(IPCNG_DIR)/Makefile
IPCNG_LIBRARY=$(IPCNG_DIR)/build/libpysamprof-ipc-ng.a

PY_BLDSHARED=$(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("BLDSHARED"))')
PY_LDFLAGS=$(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_config_var("LDFLAGS"))')

CFLAGS:=${CFLAGS} $(shell ${GET_PYCONFIG} --includes) -std=c99 -D_GNU_SOURCE -DPYSAMPROF_BUILDING_LIB=1 -g -fPIC -I$(PROTOBUF_KIT)/include -I$(IPCNG_DIR)/include -Wno-multichar -I$(COMMON_DIR)/../
LDFLAGS:=${LDFLAGS} -fPIC $(PY_LDFLAGS)
LIBS=-L${XED_LIB} -L${LIBUNWIND_LIB} -ldl -lunwind ${LIBUNWIND_NEEDS_LZMA} -lrt -L$(PROTOBUF_KIT)/lib -Wl,-Bstatic -lprotobuf-c -Wl,-Bdynamic ${LIBPROBENGINE_LIB} \
        -lxed ${SAFESTRINGLIB_LIBRARY} -lpthread

C_SOURCES = $(shell cd $(C_SOURCE_PATH); find . -maxdepth 1 -type f -name \*.c  | awk '{ sub(/.\//,"") }; 1' | grep -v sampling_thread)
C_HEADERS = $(addprefix $(C_INCLUDE_PATH)/,$(shell cd $(C_INCLUDE_PATH); find . -type f -name \*.h | awk '{ sub(/.\//,"") }; 1'))
C_OBJECTS = $(addprefix $(OBJECTS_PATH)/,$(addsuffix .o,$(basename $(C_SOURCES))))

CALLSTACK_HELPER_HEADER=$(GEN_HEADERS_PATH)/callstack_helper_gen.h

TRACE_WRITER_DIR=$(CURDIR)/../trace_writer
TRACE_WRITER_BLD=$(TRACE_WRITER_DIR)/build
TRACE_WRITER_LIBRARY=$(TRACE_WRITER_BLD)/libpysamprof-trace-client.a

${LIBPROBENGINE_LIB}: $(LIBPROBENGINE_DIR)/Makefile
	@echo Building libprobengine
	$(MAKE) -C $(LIBPROBENGINE_DIR)

$(COMMON_LIBRARY): $(COMMON_MAKEFILE)
	@echo building common
	$(MAKE) -C $(COMMON_DIR)

$(IPCNG_LIBRARY): $(IPCNG_MAKEFILE)
	@echo Building IPC-NG
	$(MAKE) -C $(IPCNG_DIR)

$(TRACE_WRITER_LIBRARY): $(TRACE_WRITER_DIR)/Makefile
	@echo building trace writer
	$(MAKE) -C $(TRACE_WRITER_DIR)

$(TARGET_PATH)/pysamprof-server: $(TRACE_WRITER_BLD)/server.exe
	@echo Making server
	mkdir -p $(TARGET_PATH)
	$(MAKE) -C $(TRACE_WRITER_DIR)
	cp $< $@

${TARGET_PATH}/${TARGET_NAME}: ${C_OBJECTS} $(COMMON_LIBRARY) $(SAFESTRINGLIB_LIBRARY) $(TRACE_WRITER_LIBRARY) $(IPCNG_LIBRARY) $(TARGET_PATH)/pysamprof-server
	@echo Linking $@...
	mkdir -p $(TARGET_PATH)
	gcc -shared ${C_OBJECTS} $(TRACE_WRITER_LIBRARY) $(IPCNG_LIBRARY) $(COMMON_LIBRARY) ${LIBS} ${LDFLAGS} -o $@

$(OBJECTS_PATH)/callstack_helper.o: $(C_SOURCE_PATH)/callstack_helper.c $(C_INCLUDE_PATH)/callstack_helper.h $(COMMON_LIBRARY) $(LIBPROBENGINE_LIB)
	@echo Compiling $<...
	mkdir -p $(OBJECTS_PATH)
	gcc $(CFLAGS) -c -I${XED_INCLUDE} -I${LIBUNWIND_INCLUDE} -I${LIBPROBENGINE} $< -o $@

$(CALLSTACK_HELPER_HEADER): $(OBJECTS_PATH)/callstack_helper.o
	@echo Generating $@...
	mkdir -p $(GEN_HEADERS_PATH)
	echo "#define PYEVAL_PROBE_SIZE 0x`objdump -h $< | grep .text | awk '{print $$3}'`" >$@

$(OBJECTS_PATH)/%.o: $(C_SOURCE_PATH)/%.c $(C_HEADERS) $(CALLSTACK_HELPER_HEADER) $(LIBPROBENGINE_LIB) $(COMMON_LIBRARY) $(SAFESTRINGLIB_LIBRARY)
	@echo Compiling $<...
	mkdir -p $(OBJECTS_PATH)
	gcc $(CFLAGS) -c -I${XED_INCLUDE} -I${LIBUNWIND_INCLUDE} -I${LIBPROBENGINE} -I${GEN_HEADERS_PATH} -I${SAFESTRINGLIB_INCLUDE} $< -o $@

clean:
	@echo Cleaning...
	rm -f ${TARGET_PATH}/${TARGET_NAME}
	rm -f ${C_OBJECTS}

run: ${TARGET_PATH}/${TARGET_NAME}
	PYTHONPATH=${TARGET_PATH} PYSAMPROF_LOGGING=- ${PYTHON} $(CURDIR)/test.py

run-sub: ${TARGET_PATH}/${TARGET_NAME}
	PYTHONPATH=${TARGET_PATH} PYSAMPROF_LOGGING=- ${PYTHON} $(CURDIR)/test_with_sub.py

dbg: ${TARGET_PATH}/${TARGET_NAME}
	PYTHONPATH=${TARGET_PATH} gdb --args ${PYTHON} $(CURDIR)/test.py

gdb: dbg

all: ${TARGET_PATH}/${TARGET_NAME}

.PHONY: clean run dbg gdb all

.DEFAULT_GOAL=all

.SILENT:
