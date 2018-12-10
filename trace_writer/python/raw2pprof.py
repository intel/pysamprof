import argparse
import gzip
import struct
import sys
import os
import subprocess
import copy
import collections
import re

import profile_pb2 as pb_profile
import sample_t_pb2 as pb_sample
import functionInfo_pb2 as pb_funcs

# message_type_t enum members from proto_message_types.h
TYPE_UNDERFINEDF, TYPE_SAMPLE, TYPE_FUNCTION_INFO, TYPE_MAPPING = [struct.unpack('>i', tag)[0] for tag in 'UNDF SMPL FNCI MAPP'.split()]
'''
    to avoid inserting "tid" and "timestamp" labels
    into string table, "tid" is always placed
    to the first row, "timestamp" to the second
    constants to avoid magic numbers:
'''
TID_LABEL_X = 1
TIMESTAMP_LABEL_X = 2
# stack_type_t enum member from sample_t.proto
STACK_TYPE_MIXED = 2
string_table = dict()

NativeFunctionInfo = collections.namedtuple('NativeFunctionInfo', 'offset size name')
NativeBinaryInfo = collections.namedtuple('NativeBinaryInfo', 'base_addr bitness functions')

def define_size_export_functions(exports, sections):
    exports.sort(key=lambda finfo: finfo.offset)
    for idx, finfo in enumerate(exports[:-1]):
        if finfo.size == 0:
            exports[idx] = finfo._replace(size=exports[idx + 1].offset - finfo.offset)

        if exports and exports[-1].size == 0:
            # last entry requires special handling
            # TODO: probably all functions should be handled the same... this should be a safe limit

            finfo = exports[-1]
            for section_id, section_addr, section_size, is_exec in sections:
                if finfo.offset >= section_addr and finfo.offset <= section_addr + section_size:
                    if is_exec:
                        exports[-1] = finfo._replace(size=section_addr + section_size - finfo.offset)
                    break
            else:
                raise ValueError("Cannot find a section that contains the function")
    return exports

if sys.platform == 'win32':
    # TODO: refactor as separate module
    def make_binary_parser():
        DUMPBIN_PATHS = (
            (r'C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\bin\amd64\dumpbin.exe',
             r'C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\bin\amd64'),
            )
        for dumpPath, dumpDir in DUMPBIN_PATHS:
            if os.path.exists(dumpPath) and os.path.exists(dumpDir):
                DUMPBIN = dumpPath, dumpDir
                break
        else:
            print("Warning: cannot find dumpbin.exe, will not be able to resolve native symbols")
            def call_parser(binary_path):
                raise NotImplementedError("dumpbin not found")
            return call_parser

        def parse_bitness_info(output):
            line_iter = iter(output.splitlines())
            for line in line_iter:
                if line.startswith('FILE HEADER VALUES'):
                    break
            else:
                raise ValueError('Missing header info')
            for line in line_iter:
                if 'machine' in line:
                    bitness = 64 if '64' in line else 32
                    break
            else:
                raise ValueError('Missing bitness info')
            return bitness

        def parse_baseaddr_info(output):
            line_iter = iter(output.splitlines())
            for line in line_iter:
                if line.startswith('OPTIONAL HEADER VALUES'):
                    break
            else:
                raise ValueError('Missing header info')
            for line in line_iter:
                if 'image base' in line:
                    base_addr = int(line.strip().split()[0].strip(), 16)
                    break
            else:
                raise ValueError('Missing base_addr info')
            return base_addr

        def parse_sections(output):
            result = []
            section_id, section_size, section_addr, header_found, is_exec = None, None, None, False, False
            for line in output.splitlines():
                if not line.strip():
                    if header_found and section_size is not None and section_addr is not None and section_id is not None:
                        result.append((section_id, section_addr, section_size, is_exec))
                    section_id, section_size, section_addr, header_found, is_exec = None, None, None, False, False
                if line.startswith('SECTION HEADER'):
                    try:
                        section_id = int(re.findall(r'(\d+)', line)[0])
                    except (IndexError, ValueError):
                        print('Warning: cannot parse section header line <%s>' % line)
                        continue
                    header_found = True
                elif header_found:
                    if 'virtual size' in line:
                        try:
                            section_size = int(line.strip().split()[0], 16)
                        except ValueError:
                            raise ValueError('Bad section: cannot parse size')
                    elif 'virtual address' in line:
                        try:
                            section_addr = int(line.strip().split()[0], 16)
                        except ValueError:
                            raise ValueError('Bad section: cannot parse address')
                    elif 'Execute' in line and 'Read' in line:
                        # previous section was "Execute Read"
                        is_exec = True

            return result

        def parse_export_functions(output):
            line_iter = iter(output.splitlines())
            for line in line_iter:
                if 'Section contains the following exports for' in line:
                    break
            else:
                raise ValueError('Can not find export section')
            function_count = None
            for line in line_iter:
                if 'number of names' in line:
                    try:
                        function_count = int(re.findall(r'(\d+)', line)[0])
                    except (ValueError, TypeError, AttributeError):
                        raise ValueError('Can not parse number of functions')
                    break
            else:
                raise ValueError('Can not find number of functions')

            for line in line_iter:
                if 'ordinal' in line and 'hint' in line and 'RVA' in line and 'name' in line:
                    break
            else:
                raise ValueError('Missing exports header')

            result = []
            for line in line_iter:
                if function_count <= 0:
                    break
                if not line.strip():
                    continue
                try:
                    ordinal, hint, rest = re.match(r'(\d+)\s*([0-9a-fA-F]+)(.*)', line.strip()).groups()
                    ordinal, hint = int(ordinal), int(hint, 16)
                except ValueError:
                    print('Warning: cannot parse ordinal and hint in <%s>' % line)
                    continue
                if rest.startswith('    '):
                    # no rva
                    rva = None
                    name = rest.split()[0]
                else:
                    try:
                        rva, name = rest.split()[:2]
                        rva = int(rva, 16)
                    except ValueError:
                        print('Warning: cannot parse rva in <%s>' % line)
                        continue
                    result.append(NativeFunctionInfo(offset=rva, size=0, name=name))

                function_count -= 1

            return result

        def parse_function_map(output, sections):
            exec_sections = frozenset(section_id for (section_id, section_addr, section_size, is_exec) in sections if is_exec)
            line_iter = iter(output.splitlines())
            for line in line_iter:
                if 'Address' in line and 'RVA' in line and 'Size' in line:
                    try:
                        next_line = next(line_iter)
                    except StopIteration:
                        return []
                    joint = ''.join(next_line.strip().split())
                    if not joint or len(joint) != joint.count('-'):
                        continue
                    break
            else:
                return []

            result = []
            for line in line_iter:
                try:
                    section_id, rva, size, rest = re.match(r'\s*(\d+):[0-9a-fA-F]+\s*([0-9a-fA-F]+)\s*[0-9a-fA-F]+\s*(\d+)\s*(.*)', line).groups()
                except AttributeError:
                    break
                if int(section_id) not in exec_sections:
                    continue
                try:
                    rva, size = int(rva, 16), int(size)
                except ValueError:
                    print('Cannot get rva and size from <%s>' % line)
                    continue
                if rest.strip():
                    name = rest.strip().split()[0]
                else:
                    name = 'func_0x%X' % rva
                result.append(NativeFunctionInfo(offset=rva, size=size, name=name))
            return result
                    
                    
        def parse_functions(output):
            exports = parse_export_functions(output)
            sections = parse_sections(output)
            mapped = parse_function_map(output, sections)

            joint = {(finfo.offset, finfo.name): finfo for finfo in exports}
            for finfo in mapped:
                joint[(finfo.offset, finfo.name)] = finfo

            result = joint.values()
            result = define_size_export_functions(result, sections)
            return result

        def call_parser(binary_path):
            env = copy.deepcopy(os.environ)
            env['PATH'] = os.pathsep.join([DUMPBIN[1], env['PATH']])
            try:
                output = subprocess.check_output([DUMPBIN[0], '/headers', '/exports', '/map', binary_path], 
                                                 env=env, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as err:
                raise ValueError("Cannot parse '%s': %s" % (binary_path, err.output))
            return NativeBinaryInfo(base_addr=parse_baseaddr_info(output), 
                                    bitness=parse_bitness_info(output), functions=parse_functions(output))

        return call_parser
else:
    def make_binary_parser():

        def parse_bitness_info(output):
            line_iter = iter(output.splitlines())
            for line in line_iter:
                if line.startswith('architecture'):
                    bitness = 64 if '64' in line else 32
                    break
            else:
                raise ValueError('Missing bitness info')
            return bitness

        def parse_baseaddr_info(output):
            line_iter = iter(output.splitlines())
            base_addr_found = False
            for line in line_iter:
                if 'Idx' in line:
                    base_addr_found = True
                    continue
                if base_addr_found:
                    temp_list = line.split()
                    base_addr = int(temp_list[3], 16) - int(temp_list[5], 16)
                    break
            else:
                raise ValueError('Missing base_addr info')
            return base_addr

        def parse_sections(output):
            result = []
            section_id, section_size, section_addr, header_found, is_exec = None, None, None, False, False
            base_addr = parse_baseaddr_info(output)
            sections_found = False
            for line in output.splitlines():
                if 'Idx' in line:
                    sections_found = True
                    continue
                if 'SYMBOL TABLE' in line:
                    break
                if sections_found:
                    if line.strip() and line.split()[0].isdigit():
                        try:
                            temp_list = line.split()
                            section_id = int(temp_list[0])
                            section_size = int(temp_list[2], 16)
                            section_addr = int(temp_list[5], 16)
                        except (IndexError, ValueError):
                            print('Warning: cannot parse section header line <%s>' % line)
                            continue
                        header_found = True
                    elif header_found:
                        if 'CODE' in line:
                            is_exec = True
                        result.append((section_id, section_addr, section_size, is_exec))
                        section_id, section_size, section_addr, header_found, is_exec = None, None, None, False, False

            return result

        def parse_export_functions(output):
            base_addr = parse_baseaddr_info(output)
            line_iter = iter(output.splitlines())
            for line in line_iter:
                if 'SYMBOL TABLE' in line:
                    break
            else:
                raise ValueError('Can not find export section')

            result = []
            for line in line_iter:
                if not line.strip():
                    continue
                try:
                    vma, flags, rest = re.match(r'([0-9a-fA-F]+)\s(.{7,7})\s(.*)', line.strip()).groups()
                    #7 - 7 bytes for flags
                    vma = int(vma, 16)
                    if vma == 0:
                        continue
                    if 'F' not in flags:
                        #F - Function
                        continue
                    name = rest.strip().split()[-1]
                    offset = vma - base_addr
                except ValueError:
                    print('Warning: cannot parse vma or size in <%s>' % line)
                    continue
                except AttributeError:
                    #unexpected string format
                    continue
                result.append(NativeFunctionInfo(offset=offset, size=0, name=name))
            return result

        def parse_functions(output):
            exports = parse_export_functions(output)
            sections = parse_sections(output)
            result = define_size_export_functions(exports, sections)
            return result

        def call_parser(binary_path):
            env = copy.deepcopy(os.environ)
            try:
                 output = subprocess.check_output(["objdump", "-fhtT", binary_path],
                                                 env=env, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as err:
                 raise ValueError("Cannot parse '%s': %s" % (binary_path, err.output))
            return NativeBinaryInfo(base_addr=parse_baseaddr_info(output),
                                    bitness=parse_bitness_info(output), functions=parse_functions(output))
        return call_parser

NATIVE_SYMBOL_PARSER = make_binary_parser()

def parse_native_symbols(mapping, funcs_info):
    try:
        binaryInfo = NATIVE_SYMBOL_PARSER(mapping.File)
    except ValueError as err:
        print("Warning: cannot parse native symbols in '%s': %s" % (mapping.File, err))
        return
    print("Parsed '%s', found %d functions" % (mapping.File, len(binaryInfo.functions)))

    for finfo in binaryInfo.functions:
        function = pb_funcs.FunctionInfo()
        function.functionId = 1
        function.functionName = finfo.name
        function.moduleInfo.moduleName = mapping.File

        region = pb_funcs.CodeRegion()
        region.startAddr = mapping.Start + finfo.offset
        region.buffer = '\xCC' * finfo.size
        function.codeInfo.codeRegions.extend([region])

        funcs_info[region.startAddr] = function


def symbolize(profile_in, input_symbols, resolve_native):
    '''
    Populates profile_in with symbol info taken from input_symbols file.
    '''
    try:
        # try gzipped if fails, try not gzipped
        with gzip.open(input_symbols, 'rb') as input_file:
            symbol_info_raw = input_file.read()
    except IOError:
        try:
            with open(input_symbols, 'rb') as input_file:
                symbol_info_raw = input_file.read()
        except:
            #pylint: disable=superfluous-parens
            print ("failed to open %s" % input_symbols)
            raise

    # dictionary for function address->function structure mapping
    funcs_info = {}
    # list of already added to profile functions
    funcs_in_profile = []
    cur_func_id = 0
    for function in profile_in.Function:
        funcs_in_profile.append(function.ID)
        if cur_func_id < function.ID:
            cur_func_id = function.ID
    cur_func_id += 1

    cur_map_id = 0
    for profile_mapping in profile_in.Mapping:
        if profile_mapping.ID >= cur_map_id:
            cur_map_id = profile_mapping.ID
    cur_map_id += 1

    offset = 0

    mappings = []
    native_symbols = set()
    while offset < len(symbol_info_raw):
        (message_type, message_len) = struct.unpack_from('iI', symbol_info_raw, offset)
        offset += struct.calcsize('iI')
        if message_type == TYPE_FUNCTION_INFO:
            function = pb_funcs.FunctionInfo()
            function.ParseFromString(symbol_info_raw[offset : offset + message_len])
            funcs_info[function.codeInfo.codeRegions[0].startAddr] = function
        elif message_type == TYPE_MAPPING:
            mapping = pb_funcs.Mapping()
            mapping.ParseFromString(symbol_info_raw[offset : offset + message_len])
            mappings.append(mapping)
            if resolve_native:
                if mapping.File not in native_symbols:
                    parse_native_symbols(mapping, funcs_info)
                    native_symbols.add(mapping.File)
        else:
            #pylint: disable=superfluous-parens
            print ("unknown message type: %s", struct.pack('>i', message_type))

        offset += message_len

    mappings.sort(key=lambda m: m.Start)
    skipped = set()
    for idx, mapping in enumerate(mappings):
        if id(mapping) in skipped:
            continue
        real_start = mapping.Start - mapping.Offset
        for next_mapping in mappings[idx + 1:]:
            if id(mapping) in skipped:
                continue
            if next_mapping.Start == mapping.Limit:
                if next_mapping.File == mapping.File and \
                        next_mapping.Start - next_mapping.Offset == real_start:
                    mapping.Limit = next_mapping.Limit
                    skipped.add(id(next_mapping))

        profile_mapping = profile_in.Mapping.add()
        profile_mapping.ID = cur_map_id
        cur_map_id += 1
        profile_mapping.Start = mapping.Start
        profile_mapping.Limit = mapping.Limit
        profile_mapping.Offset = mapping.Offset
        profile_mapping.fileX = get_string_table_index(mapping.File)
        profile_mapping.HasFunctions = False
        profile_mapping.HasFilenames = False
        profile_mapping.HasLineNumbers = False
        profile_mapping.HasInlineFrames = False

    for location in profile_in.Location: #pylint: disable=no-member
        for mapping in profile_in.Mapping:
            if location.Address >= mapping.Start and location.Address <= mapping.Limit:
                location.mappingIDX = mapping.ID
                break
        update_location(location, profile_in,
                        cur_func_id,
                        funcs_in_profile, funcs_info)
        cur_func_id += 1

    return profile_in


def update_location(location, profile, uid, funcs_in_profile, funcs_info):
    '''
    Add location object to profile and function corresponding to
    location if it was not added yet.
    '''
    for function_start in funcs_info.keys():
        if len(funcs_info[function_start].codeInfo.codeRegions) != 1:
            #pylint: disable=superfluous-parens
            raise Exception("expected len of code region equal 1, got %d: ", 
                    len(funcs_info[function_start].codeInfo.codeRegions))
        function_end = function_start + \
                        len(funcs_info[function_start].codeInfo.codeRegions[0].buffer)
        if location.Address >= function_start and location.Address <= function_end:
            function = funcs_info[function_start]
            start_address = function_start
            break
    else:
        return
    profile_line = location.Line.add()
    # look for number line
    for mapping in function.lineNumbermappings.nativeToSourceMap:
        line_start = start_address + mapping.startOffset
        line_end = start_address + mapping.endOffset
        if location.Address >= line_start and location.Address <= line_end:
            profile_line.Line = mapping.lineNumber
            break
    profile_line.functionIDX = uid
    if uid not in funcs_in_profile:
        funcs_in_profile.append(add_function(uid, function, profile))


def add_function(uid, function, profile):
    '''
    Add function object to profile. Returns id of added function.
    '''
    profile_function = profile.Function.add()
    profile_function.ID = uid
    profile_function.nameX = get_string_table_index(function.functionName)
    profile_function.filenameX = get_string_table_index(function.sourceFileInfo.sourceFileName)
    if len(function.lineNumbermappings.nativeToSourceMap) != 0:
        profile_function.StartLine = function.lineNumbermappings.nativeToSourceMap[0].lineNumber
    return profile_function.ID


def get_string_table_index(record):
    '''
    All strings are represented as indexes in string table.
    Function returns index if record exists and adds new and returns
    its index otherwise.
    '''
    global string_table
    try:
        return string_table[record]
    except KeyError:
        result = len(string_table)
        string_table[record] = result
        return result


def add_period_type(profile):
    '''
    Adds default period type to profile.
    '''
    period_type = "cpu"
    period_unit = "nanoseconds"
    profile.PeriodType.typeX = get_string_table_index(period_type)
    profile.PeriodType.unitX = get_string_table_index(period_unit)


def init_profile(profile_time, profile_period):
    '''
    Creats profiles, fills in time, period, period type and
    string table default lines.
    '''
    global string_table
    if string_table:
        raise Exception("Cannot process two profiles at the same time")
    profile = pb_profile.Profile()
    profile.TimeNanos = profile_time
    profile.Period = profile_period
    for item in ["", "tid", "timestamp"]:
        string_table[item] = len(string_table)
    add_period_type(profile)
    return profile


def add_sample_type(profile, type_sample, unit_sample):
    '''
    Adds sample type with given type and unit.
    '''
    sample_type = profile.SampleType.add()
    sample_type.typeX = get_string_table_index(type_sample)
    sample_type.unitX = get_string_table_index(unit_sample)


def add_num_label(sample, key, number, string_table):
    '''
    Adds numeric label to sample.
    '''
    label = sample.labelX.add()
    label.keyX = get_string_table_index(key, string_table)
    label.numX = number


def add_sample(profile, sample, seen_locations):
    '''
    Adds sample to profile, takes seen_locations dict
    to avoid insertion of the same locations many times.
    '''
    if sample.stack_type != STACK_TYPE_MIXED:
        #pylint: disable=superfluous-parens
        print ("only mixed stack type is supported now")
        return
    profile_sample = profile.Sample.add()
    profile_sample.Value.extend([1, sample.duration])
    for location in sample.locations:
        try:
            uid = seen_locations[location]
        except KeyError:
            profile_location = profile.Location.add()
            uid = len(seen_locations) + 1
            seen_locations[location] = uid
            profile_location.Address = location
            profile_location.ID = uid
        profile_sample.locationIDX.append(uid)
    tid_label = profile_sample.labelX.add()
    tid_label.keyX = TID_LABEL_X
    tid_label.numX = sample.tid
    timestamp_label = profile_sample.labelX.add()
    timestamp_label.keyX = TIMESTAMP_LABEL_X
    timestamp_label.numX = sample.timestamp


def convert(input_file_name):
    '''
    Converts raw trace to pprof profile and
    write it to output file.
    '''
    try:
        with gzip.open(input_file_name, 'rb') as input_file:
            data = input_file.read()
    except IOError:
        try:
            with open(input_file_name, 'rb') as input_file:
                data = input_file.read()
        except:
            #pylint: disable=superfluous-parens
            print ("failed to open %s" % input_file_name)
            raise

    offset = 0
    if len(data) < struct.calcsize('qq'):
        #pylint: disable=superfluous-parens
        print ("failed to read time and period, too short trace\n")
        exit()
    (profile_time, profile_period) = struct.unpack_from('qq', data, offset)
    offset += struct.calcsize('qq')
    seen_locations = dict()
    profile = init_profile(profile_time, profile_period)
    add_sample_type(profile, "samples", "count")
    add_sample_type(profile, "cpu", "nanoseconds")
    while offset < len(data):
        (message_type, message_len) = struct.unpack_from('iI', data, offset)
        offset += struct.calcsize('iI')
        if message_type == TYPE_SAMPLE:
            sample = pb_sample.sample_t()
            sample.ParseFromString(data[offset: offset + message_len])
            add_sample(profile, sample, seen_locations)
        else:
            #pylint: disable=superfluous-parens
            print ("unknowm message type: %s", struct.pack('>i', message_type))
        offset += message_len
    return profile


def write_profile(profile, output_file_name):
    '''
    Serializes, gzips and writes profile to output_file_name.
    '''
    global string_table
    for name, nameX in sorted(string_table.items(), key=lambda elem: elem[1]):
        profile.stringTable.append(name)
    string_table = {}
    out_data = profile.SerializeToString()
    try:
        with gzip.open(output_file_name, 'wb') as output_file:
            output_file.write(out_data)
    except IOError:
        #pylint: disable=superfluous-parens
        print ("failed to write profile to %s" % output_file_name)


def main():
    '''
    Main function adds and parses args.
    Makes conversion, symbolization of traces.
    Writes profile in pprof format to file.
    '''
    parser = argparse.ArgumentParser(description='Convert \
                     raw trace to profile')
    parser.add_argument('--raw', dest='raw', required=True,
                        help='raw trace')
    parser.add_argument('--symbols', dest='symbols', required=True,
                        help='symbols in pprof')
    parser.add_argument('--out', dest='pprof', required=True,
                        help='out file in gzipped pprof')
    parser.add_argument('--resolve', dest='resolve_native', action='store_const',
                        const=True, default=False,
                        help='Resolve native frames using platform tools')
    args = parser.parse_args()
    profile = convert(args.raw)
    profile = symbolize(profile, args.symbols, args.resolve_native)
    write_profile(profile, args.pprof)

if __name__ == '__main__':
    main()
