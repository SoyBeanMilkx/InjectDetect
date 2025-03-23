#include <string>
#include "utils.h"

std::string result = "result: \n";
bool is_env_abnormal = false;

static int callback(struct dl_phdr_info *info, size_t size, void *data) {

    if(is_linker_sensitive(info->dlpi_name, linker_sensitive_lib)){ // 检查solist是否含有敏感so
        result += "detect sensitive lib from linker\n";
        is_env_abnormal |= true;
        return 1;
    }

    return 0;
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_yuuki_check_1env_MainActivity_is_1env_1abnormal(
        JNIEnv* env,
        jobject) {

    generate_crc32_table(); //初始化CRC32表

    dl_iterate_phdr(callback, NULL);

    if(is_maps_sensitive(maps_sensitive_words, self_maps)){ // 检查maps是否有敏感so
        result += "detect suspicious maps\n";
        is_env_abnormal |= true;
    }
    if(is_maps_sensitive(maps_sensitive_words, self_smaps)){ // 检查smaps是否有敏感so
        result += "detect suspicious smaps\n";
        is_env_abnormal |= true;
    }

    if(has_anon_exec_memory(self_maps)){ // 检查maps是否含有可疑匿名段
        result += "detect maps anonymous executable memory\n";
        is_env_abnormal |= true;
    }
    if(has_anon_exec_memory(self_smaps)){ // 检查smaps是否含有可疑匿名段
        result += "detect smaps anonymous executable memory\n";
        is_env_abnormal |= true;
    }


    if(scan_mem_keywords(mem_sensitive_words)){ // 暴力搜索内存查看是否含有敏感字符，但是即使搜到单凭这一点也无法断定被注入
        result += "detect suspicious mem\n";
        is_env_abnormal |= true;
    }

    if(scan_task_status(sensitive_task_name)){ // 检查线程名
        result += "detect suspicious task\n";
        is_env_abnormal |= true;
    }

    if(check_all_libs_integrity(crc_solist)){ // CRC检测
        result += "detect lib has bean hooked\n";
        is_env_abnormal |= true;
    }

    LOGD(LOG_TAG "%s", result.c_str());

    return env->NewStringUTF(result.c_str());
}

/*
     TODO
     1.在init_array里创建线程检测
     2.动态监听堆栈内存情况，突然变化则可能存在注入
     3.在init_array里检查线程数目，通常app刚启动时线程数相对固定
     4.暴力搜索内存中elf的个数，但是不同厂商加载的个数似乎本身就不一样

*/