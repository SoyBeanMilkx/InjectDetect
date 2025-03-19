# InjectDetect
检测app是否被frida/xposed注入

## 检测点：

- [x]  检查maps是否有敏感so
  
- [x] 检查smaps是否有敏感so
  
- [x] 检查solist是否含有敏感so
  
- [x] 检查maps是否含有可疑内存段
  
- [x] 检查smaps是否含有可疑内存段
  
- [x] 暴力搜索内存查看是否含有敏感字符
  
- [x] 检查线程名
  
- [x] CRC校验
