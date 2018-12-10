PROTOBUF_KIT=$(CURDIR)/../build/protobuf-ckit

IPCNG_DIR=$(CURDIR)/../libipc-ng
IPCNG_MAKEFILE=$(IPCNG_DIR)/Makefile
IPCNG_LIBRARY=$(IPCNG_DIR)/build/libpysamprof-ipc-ng.a

TARGET_PATH?=build/
OBJECTS_PATH=$(TARGET_PATH)/obj/
TARGET_LIBRARY=libpysamprof-trace-client.a

SAFESTRINGLIB_ROOT?=$(CURDIR)/../3rd_party/safestringlib
SAFESTRINGLIB_INCLUDE?=${SAFESTRINGLIB_ROOT}/include
SAFESTRINGLIB_LIBRARY?=${SAFESTRINGLIB_ROOT}/libsafestring.a

COMMON_DIR=$(CURDIR)/../common
COMMON_MAKEFILE=$(COMMON_DIR)/Makefile
COMMON_LIBRARY=$(COMMON_DIR)/build/libpysamprof-common.a

CFLAGS:=${CFLAGS} -std=gnu99 -Wall -g -fPIC -I${IPCNG_DIR}/include -Wno-multichar -I$(COMMON_DIR)/../
INCLUDE_FLAGS=-I$(PROTOBUF_KIT)/include -I$(SAFESTRINGLIB_INCLUDE)
LDFLAGS:=${LDFLAGS} -fPIC -L$(PROTOBUF_KIT)/lib
LIBS=-Wl,-Bstatic -lprotobuf-c -Wl,-Bdynamic ${IPCNG_LIBRARY} -lrt -lanl -lpthread ${SAFESTRINGLIB_LIBRARY}

C_SOURCE_PATH?=$(CURDIR)
C_INCLUDE_PATH=$(C_SOURCE_PATH)
C_SOURCES = $(shell cd $(C_SOURCE_PATH); find . -mindepth 2 -type f -name \*.c | awk '{ sub(/.\//,"") }; 1')
C_PART_HEADERS = $(addprefix $(C_INCLUDE_PATH)/,$(shell cd $(C_INCLUDE_PATH); find . -type f -name \*.h | awk '{ sub(/.\//,"") }; 1'))
C_PART_OBJECTS = $(addprefix $(OBJECTS_PATH)/,$(addsuffix .o,$(basename $(C_SOURCES))))
C_OBJECTS = $(C_PART_OBJECTS)

C_HEADERS = $(C_PART_HEADERS) $(wildcard $(C_SOURCE_PATH)/../ipc/*.h)

LIBONLY_OBJECTS := $(foreach f,$(C_OBJECTS),$(if $(findstring $(OBJECTS_PATH)/src,$f),,$f))

$(COMMON_LIBRARY): $(COMMON_MAKEFILE)
	@echo building common
	$(MAKE) -C $(COMMON_DIR)

$(IPCNG_LIBRARY): $(IPCNG_MAKEFILE)
	@echo Building IPC-NG
	$(MAKE) -C $(IPCNG_DIR)

clean:
	@echo Cleaning
	rm -rf $(TARGET_PATH)

define compile-obj
@echo Compiling $<
mkdir -p $(dir $@)
gcc $(CFLAGS) -c ${INCLUDE_FLAGS} $< -o $@
endef

$(OBJECTS_PATH)/proto/%.o: $(C_SOURCE_PATH)/proto/%.c $(C_HEADERS) $(COMMON_LIBRARY)
	$(compile-obj)

$(OBJECTS_PATH)/src/%.o: $(C_SOURCE_PATH)/src/%.c $(C_HEADERS) $(COMMON_LIBRARY) $(SAFESTRINGLIB_LIBRARY)
	$(compile-obj)

$(TARGET_PATH)/server.exe: $(C_OBJECTS) $(IPCNG_LIBRARY)
	@echo Linking $@
	gcc -o $@ $(LDFLAGS) $(LIBONLY_OBJECTS) $(OBJECTS_PATH)/src/ipc_message.o $(OBJECTS_PATH)/src/writing_thread.o $(OBJECTS_PATH)/src/server_handles.o $(OBJECTS_PATH)/src/server.o $(LIBS) $(COMMON_LIBRARY) 

$(TARGET_PATH)/client.exe: $(C_OBJECTS) $(IPCNG_LIBRARY) 
	@echo Linking $@
	gcc -o $@ $(LDFLAGS) $(LIBONLY_OBJECTS) $(OBJECTS_PATH)/src/ipc_message.o $(OBJECTS_PATH)/src/client_handles.o $(OBJECTS_PATH)/src/client.o $(OBJECTS_PATH)/src/client_test.o $(LIBS) $(COMMON_LIBRARY) 

$(TARGET_PATH)/trace_reader.exe: $(C_OBJECTS) $(IPCNG_LIBRARY)  
	@echo Linking $@
	gcc -o $@ $(LDFLAGS) $(LIBONLY_OBJECTS) $(OBJECTS_PATH)/src/read_trace.o $(LIBS) $(COMMON_LIBRARY)

$(TARGET_PATH)/$(TARGET_LIBRARY): $(C_OBJECTS)
	@echo Making library $@
	ar rcs $@ $(OBJECTS_PATH)/src/client_handles.o $(OBJECTS_PATH)/src/ipc_message.o $(OBJECTS_PATH)/src/client.o $(OBJECTS_PATH)/src/function_info.o $(OBJECTS_PATH)/proto/functionInfo.pb-c.o

all: $(TARGET_PATH)/server.exe $(TARGET_PATH)/client.exe $(TARGET_PATH)/trace_reader.exe $(TARGET_PATH)/$(TARGET_LIBRARY)

.PHONY: all clean

.DEFAULT_GOAL := all

.SILENT:
