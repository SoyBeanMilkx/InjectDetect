#ifndef CHECK_ENV_UTILS_H
#define CHECK_ENV_UTILS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/elf.h>
#include <sys/mman.h>
#include <dirent.h>
#include <link.h>

#include "CRC32.h"

#define LOG_TAG "yuuki_env"
#define APP_NAME "check_env"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#define self_maps "/proc/self/maps"
#define self_smaps "/proc/self/smaps"
#define self_mem "/proc/self/mem"
#define self_task "/proc/self/task"
#define task_status "/proc/self/task/%s/status"

#define NO_COUNT 0
#define COUNT 1

#define MAX_LINE 256

#ifdef __cplusplus
extern "C" {
#endif

char *find_path_from_maps(const char *soname);
struct map_info find_info_from_maps(const char *soname, const char *perm);
int is_linker_sensitive(const char* soname, const char** sensitive_words);
int is_maps_sensitive(const char** sensitive_words, const char* map_name);
int count_maps_sensitive(const char* sensitive_word, char is_count, const char* map_name);
int has_anon_exec_memory(const char* map_name);
int scan_mem_keywords(const char** keywords);
int scan_task_status(const char** task_name);
int check_lib_integrity(const char *soname);
int check_all_libs_integrity(const char** so_name_list);
size_t get_symbol_offset(const char *file_path, const char *symbol_name);
size_t get_func_address(const char *soname, const char *symbol_name);

#ifdef __cplusplus
}
#endif

static const char* maps_sensitive_words[] = {
        "frida", "rwxp", "zygisk", "lsposed", "/data/local/tmp", "/data/adb/", NULL
};

static const char* linker_sensitive_lib[] = {
        "frida", "zygisk", "lsposed", "/data/local/tmp", "/data/adb/", NULL
};

static const char* sensitive_task_name[] = {
        "gmain", "gdbus", "gum-js-loop", "pool-frida", NULL
};

static const char* mem_sensitive_words[] = {
        "frida", "zygisk", "lsposed", "/data/local/tmp", "/data/adb/", NULL
};

static const char* crc_solist[] = {
        "libart.so", "libc.so", "libcheck_env.so", NULL
};

struct map_info {
    uint64_t start;
    uint64_t size;
    uint64_t offset;
    char pathname[256];
};



#endif
