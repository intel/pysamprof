TARGET_PATH?=build
OBJECTS_PATH=$(TARGET_PATH)/obj
C_SOURCE_PATH?=$(CURDIR)
C_SOURCE_DIRS=$(subst ./, ,$(shell cd $(C_SOURCE_PATH); find . -type d ! -path "*$(TARGET_PATH)*" ! -path "*tests*"))
C_SOURCES=$(subst ./, ,$(shell cd $(C_SOURCE_PATH); find . -type f -name \*.c ! -path "*$(TARGET_PATH)*" ! -path "*tests*"))
C_OBJ_FILES=$(patsubst %.c,%.o,$(wildcard $(C_SOURCES)))
C_OBJS=$(addprefix $(OBJECTS_PATH)/, $(C_OBJ_FILES))

SAFESTRINGLIB_ROOT?=$(CURDIR)/../3rd_party/safestringlib
SAFESTRINGLIB_INCLUDE?=${SAFESTRINGLIB_ROOT}/include
SAFESTRINGLIB_LIBRARY?=${SAFESTRINGLIB_ROOT}/libsafestring.a

TARGET_LIB=$(TARGET_PATH)/libpysamprof-common.a

CFLAGS:=${CFLAGS} -std=c99 -Wall -g -fPIC

$(OBJECTS_PATH)/%.o: $(C_SOURCE_PATH)/%.c
	mkdir -p $(dir $@)
	@echo Compiling $@...
	gcc $(CFLAGS) -c $< $(addprefix -I,$(C_SOURCE_DIRS)) -I$(SAFESTRINGLIB_INCLUDE) -o $@

clean:
	@echo Cleaning...
	rm -rf $(TARGET_PATH)

all: $(TARGET_LIB)

$(TARGET_LIB): $(C_OBJS)
	@echo Building $@...
	ar rcs $@ $(C_OBJS)

CXXFLAGS= -std=c++11

.PHONY: clean all
.DEFAULT_GOAL=all
.SILENT:
