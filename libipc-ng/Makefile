TARGET_PATH?=$(CURDIR)/build
OBJECTS_PATH=$(TARGET_PATH)/obj
C_SOURCE_PATH?=$(CURDIR)
C_SOURCE_DIRS=$(subst ./, ,$(shell cd $(C_SOURCE_PATH); find . -type d ! -path "*$(TARGET_PATH)*" ! -path "*unit_tests*"))
C_SOURCES=$(subst ./, ,$(shell cd $(C_SOURCE_PATH); find . -maxdepth 1 -type f -name \*.c ! -path "*$(TARGET_PATH)*" ! -path "*unit_tests*"))
C_OBJ_FILES=$(patsubst %.c,%.o,$(wildcard $(C_SOURCES)))
C_OBJS=$(addprefix $(OBJECTS_PATH)/, $(C_OBJ_FILES))

SAFESTRINGLIB_ROOT?=$(CURDIR)/../3rd_party/safestringlib
SAFESTRINGLIB_INCLUDE?=${SAFESTRINGLIB_ROOT}/include
SAFESTRINGLIB_LIBRARY?=${SAFESTRINGLIB_ROOT}/libsafestring.a

COMMON_DIR=$(CURDIR)/../common
COMMON_MAKEFILE=$(COMMON_DIR)/Makefile
COMMON_LIBRARY=$(COMMON_DIR)/build/libpysamprof-common.a

TARGET_LIB=$(TARGET_PATH)/libpysamprof-ipc-ng.a

CFLAGS:=${CFLAGS} -std=c99 -Wall -g -fPIC -I$(C_SOURCE_PATH)/include

$(COMMON_LIBRARY): $(COMMON_MAKEFILE)
	@echo building common
	$(MAKE) -C $(COMMON_DIR)

$(OBJECTS_PATH)/%.o: $(C_SOURCE_PATH)/%.c
	mkdir -p $(dir $@)
	@echo Compiling $@...
	gcc $(CFLAGS) -c $< $(addprefix -I,$(C_SOURCE_DIRS)) -I$(SAFESTRINGLIB_INCLUDE) -o $@

clean:
	@echo Cleaning...
	rm -rf $(TARGET_PATH)

$(TARGET_PATH)/checker: $(TARGET_LIB) $(COMMON_LIBRARY) $(SAFESTRINGLIB_LIBRARY)
	@echo Linking $@
	mkdir -p $(TARGET_PATH)
	gcc ${LDFLAGS} $(TARGET_LIB) $(COMMON_LIBRARY) -lpthread -lrt $(SAFESTRINGLIB_LIBRARY) -o $@

all: $(TARGET_LIB)


$(TARGET_LIB): $(C_OBJS)
	@echo Building $@...
	ar rcs $@ $(C_OBJS)

CXXFLAGS= -std=c++11 -Wall -g -fPIC

.PHONY: clean all
.DEFAULT_GOAL=all
.SILENT:
