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

COMMON_DIR=$(CURDIR)/../common
COMMON_MAKEFILE=$(COMMON_DIR)/Makefile
COMMON_LIBRARY=$(COMMON_DIR)/build/libpysamprof-common.a

C_SOURCE_PATH?=$(CURDIR)
C_INCLUDE_PATH=$(shell cd "$(C_SOURCE_PATH)/include"; pwd)
OBJECTS_PATH?=build/obj
TARGET_PATH?=build
TARGET_NAME:=main
PROJECT_NAME:=probengine
TARGET_LIBRARY:=libpysamprof-${PROJECT_NAME}.a

PYTHON_CONFIG?=python-config

CFLAGS:=${CFLAGS} $(shell ${PYTHON_CONFIG} --cflags) -std=gnu99 -D_GNU_SOURCE -Wall -g -fPIC -I${COMMON_DIR}/../
LDFLAGS:=${LDFLAGS}
LIBS=$(shell ${PYTHON_CONFIG} --ldflags) -L${XED_LIB} -L${LIBUNWIND_LIB} -lxed -ldl -lrt -lunwind ${LIBUNWIND_NEEDS_LZMA} ${COMMON_LIBRARY} ${SAFESTRINGLIB_LIBRARY}

C_SOURCES = $(shell cd $(C_SOURCE_PATH); find . -type f -name \*.c | awk '{ sub(/.\//,"") }; 1')
C_LIB_SOURCES = $(shell cd $(C_SOURCE_PATH); find . -type f -name \*.c | grep -v main | awk '{ sub(/.\//,"") }; 1')
C_HEADERS = $(addprefix $(C_INCLUDE_PATH)/,$(shell cd $(C_INCLUDE_PATH); find . -type f -name \*.h | awk '{ sub(/.\//,"") }; 1'))
C_OBJECTS = $(addprefix $(OBJECTS_PATH)/,$(addsuffix .o,$(basename $(C_SOURCES))))
C_LIB_OBJECTS = $(addprefix $(OBJECTS_PATH)/,$(addsuffix .o,$(basename $(C_LIB_SOURCES))))
C_INSTALL_HEADERS = $(addprefix ${TARGET_PATH}/${PROJECT_NAME}/, $(notdir ${C_HEADERS}))

$(COMMON_LIBRARY): $(COMMON_MAKEFILE)
	@echo building common
	$(MAKE) -C $(COMMON_DIR)

$(OBJECTS_PATH)/%.o: $(C_SOURCE_PATH)/%.c $(C_HEADERS) $(COMMON_LIBRARY) $(SAFESTRINGLIB_LIBRARY)
	@echo Compiling $<...
	mkdir -p $(OBJECTS_PATH)
	gcc $(CFLAGS) -c -I${XED_INCLUDE} -I${LIBUNWIND_INCLUDE} -I${SAFESTRINGLIB_INCLUDE} -I${C_INCLUDE_PATH} $< -o $@

${TARGET_PATH}/${TARGET_NAME}: ${C_OBJECTS} ${COMMON_LIBRARY} ${SAFESTRINGLIB_LIBRARY}
	@echo Linking $@...
	mkdir -p $(TARGET_PATH)
	gcc ${LDFLAGS} ${C_OBJECTS} ${LIBS} -rdynamic -o $@

${TARGET_PATH}/${TARGET_LIBRARY}: ${C_LIB_OBJECTS} ${COMMON_LIBRARY} ${SAFESTRINGLIB_LIBRARY}
	@echo Creating $@...
	mkdir -p $(TARGET_PATH)
	ar rcs $@ ${C_LIB_OBJECTS}

clean:
	@echo Cleaning...
	rm -f ${TARGET_PATH}/${TARGET_NAME}
	rm -f ${TARGET_PATH}/${TARGET_LIBRARY}
	rm -f ${C_OBJECTS}
	rm -rf ${TARGET_PATH}/${PROJECT_NAME}

${C_INSTALL_HEADERS}: ${C_HEADERS}
	@echo Copying headers
	mkdir -p ${TARGET_PATH}/${PROJECT_NAME}
	cp ${C_HEADERS} ${TARGET_PATH}/${PROJECT_NAME}

run: ${TARGET_PATH}/${TARGET_NAME}
	${TARGET_PATH}/${TARGET_NAME}

all: ${TARGET_PATH}/${TARGET_NAME} ${TARGET_PATH}/${TARGET_LIBRARY} ${C_INSTALL_HEADERS}

.PHONY: clean run all

.DEFAULT_GOAL := all

.SILENT:
