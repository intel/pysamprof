#include <stdlib.h>
#include <stdio.h>

#include <utilities/inttype_helper.h>
#include <status/status.h>

#include "../include/proto_message_types.h"

#include "../proto/functionInfo.pb-c.h"
#include "../proto/sample_t.pb-c.h"

void print_sample_t(Perftools__Samples__SampleT *sampleT)
{
    uint32_t i;

    if (sampleT->has_stack_size)
    {
        printf("Stack size: %" PRIu64 "\n", sampleT->stack_size);
    }
    if (sampleT->has_stack_type)
    {
        printf("Stack type: %" PRIu32 "\n", sampleT->stack_type);
    }
    if (sampleT->has_duration)
    {
        printf("Duration: %" PRId64 "\n", sampleT->duration);
    }
    if (sampleT->has_timestamp)
    {
        printf("Timestamp: %" PRId64 "\n", sampleT->timestamp);
    }
    if (sampleT->has_tid)
    {
        printf("Tid: %" PRId64 "\n", sampleT->tid);
    }
    for (i = 0; i < sampleT->n_locations; i++)
    {
        printf("Location with address: %" PRIu64 "\n", sampleT->locations[i]);
    }
    printf("--------------------------------------\n");
}

void print_mapping_info_t(Perftools__Symbols__Mapping *info)
{
    if (info->has_start)
    {
        printf("Mapping start: %" PRIu64 "\n", info->start);
    }
    if (info->has_limit)
    {
        printf("Mapping limit: %" PRIu64 "\n", info->limit);
    }
    if (info->has_offset)
    {
        printf("Mapping offset: %" PRIu64 "\n", info->offset);
    }
    if (info->has_loadtime)
    {
        printf("Mapping loadtime: %" PRId64 "\n", info->loadtime);
    }
    if (info->file)
    {
        printf("Mapping file name: %s \n", info->file);
    }
    printf("--------------------------------------\n");
}

void print_function_info_t(Perftools__Symbols__FunctionInfo *info)
{
    if (info->has_functionid)
    {
        printf("Function id: %" PRIu64 "\n", info->functionid);
    }
    if (info->functionname)
    {
        printf("Function name: %s \n", info->functionname);
    }
    if (info->sourcefileinfo)
    {
        printf("Source: %s \n", info->sourcefileinfo->sourcefilename);
    }
    if (info->codeinfo && info->codeinfo->coderegions)
    {
        uint32_t i;
        for (i = 0; i < info->codeinfo->n_coderegions; i++)
        {
            printf("Function startaddr: %" PRIu64 " endaddr: %" PRIu64 "\n",
                    info->codeinfo->coderegions[i]->startaddr,
                    info->codeinfo->coderegions[i]->startaddr
                            + info->codeinfo->coderegions[i]->buffer.len);
        }
    }
    printf("--------------------------------------\n");
}

operation_result_t read_trace(char* file_name, int has_time_and_period)
{
    FILE *fp;
    message_type_t type = type_undefined;
    uint32_t length = 0;
    size_t count = 0;
    uint32_t buf_size = 1024;
    uint8_t *buf;

    Perftools__Samples__SampleT *sampleT;
    Perftools__Symbols__FunctionInfo *info;
    Perftools__Symbols__Mapping *mapping;


    if (!file_name)
    {
        printf("File name pointer is NULL\n");
        return or_fail;
    }
    printf("Reading '%s' file........\n", file_name);
    fp = fopen(file_name, "rb");
    if (fp == NULL) return or_cannot_open_file;

    if (has_time_and_period != 0)
    {
        int64_t time, period;
        if (fread(&time, sizeof(int64_t), 1, fp) != 1)
        {
            printf("Cannot read time from trace file '%s'\n", file_name);
            fclose(fp);
            return or_io_fail;
        }
        if (fread(&period, sizeof(int64_t), 1, fp) != 1)
        {
            printf("Cannot read period from trace file '%s'\n", file_name);
            fclose(fp);
            return or_io_fail;
        }
        printf("time: %lld, period: %lld\n\n", (long long)time, (long long)period);
    }

    buf = (uint8_t*)malloc(sizeof(uint8_t) * buf_size);
    if (buf == NULL)
    {
        fclose(fp);
        return or_insufficient_memory;
    }

    while (fread(&type, sizeof(message_type_t), 1, fp) == 1)
    {
        if ((type != type_sample) && (type != type_function_info) && (type != type_mapping))
        {
            free(buf);
            fclose(fp);
            printf("Unknown message type in trace '%s'\n", file_name);
            return or_unknown_message;
        }
        count = fread(&length, sizeof(uint32_t), 1, fp);
        if (count != 1)
        {
            free(buf);
            fclose(fp);
            printf("Failed to read message length in trace '%s'\n", file_name);
            return or_io_fail;
        }
        while (buf_size <= length)
        {
            uint8_t *new_buf;

            buf_size *= 2;
            new_buf = (uint8_t*)realloc(buf, sizeof(uint8_t) * buf_size);
            if (new_buf == NULL)
            {
                free(buf);
                fclose(fp);
                printf("Failed to realloc buffer for message\n");
                return or_insufficient_memory;
            }
            buf = new_buf;
        }
        count = fread(buf, sizeof(uint8_t), length, fp);
        if (count != length)
        {
            free(buf);
            fclose(fp);
            printf("Failed to read message from trace '%s'\n", file_name);
            return or_io_fail;
        }
        switch (type)
        {
        case type_sample:
            sampleT = perftools__samples__sample_t__unpack(NULL, length, buf);
            if (sampleT == NULL)
            {
                free(buf);
                fclose(fp);
                printf("Failed to unpack sample message\n");
                return or_protobuf_fail;
            }
            print_sample_t(sampleT);
            perftools__samples__sample_t__free_unpacked(sampleT, NULL);
            break;
        case type_function_info:
            info = perftools__symbols__function_info__unpack(NULL, length, buf);
            if (info == NULL)
            {
                free(buf);
                fclose(fp);
                printf("Failed to unpack function info message\n");
                return or_io_fail;
            }
            print_function_info_t(info);
            perftools__symbols__function_info__free_unpacked(info, NULL);
            break;
        case type_mapping:
            mapping = perftools__symbols__mapping__unpack(NULL, length, buf);
            if (mapping == NULL)
            {
                free(buf);
                fclose(fp);
                printf("Failed to unpack mapping message\n");
                return or_io_fail;
            }
            print_mapping_info_t(mapping);
            perftools__symbols__mapping__free_unpacked(mapping, NULL);
            break;
        default:
            free(buf);
            fclose(fp);
            printf("Unknown message type in trace '%s'\n", file_name);
            return or_unknown_message;
            break;
        }
    }
    free(buf);
    fclose(fp);
    return or_okay;
}

int main(int argc, char *argv[])
{
    operation_result_t status;
    if (argc != 3) /* argc should be 3 for correct execution */
    {
        printf("usage: %s tracename symboltracename\n", argv[0]);
    }
    else
    {
        // read traces
        printf("\nReading samples....\n");
        status = read_trace(argv[1], 1);
        if (status != or_okay)
        {
            printf("Something went wrong...got status %d in read_trace!\n", status);
            return 1;
        }
        printf("\nDone\n");
        printf("\nReading symbol info....\n");
        status = read_trace(argv[2], 0);
        if (status != or_okay)
        {
            printf("Something went wrong...got status %d in read_trace!\n", status);
            return 1;
        }
        printf("\nDone\n");
        printf("Ok\n");
    }
    return 0;
}
