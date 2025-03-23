# InjectDetect
检测主要针对frida和xposed，当然一些未做处理的普通注入也可以检测到，可能会存在一些bug

## 检测点：

- [x] 检查maps是否有敏感so
  
- [x] 检查smaps是否有敏感so
  
- [x] 检查solist是否含有敏感so
  
- [x] 检查maps是否含有可疑内存段
  
- [x] 检查smaps是否含有可疑内存段
  
- [x] 检查内存是否含有敏感字符
  
- [x] 检查线程名
  
- [x] CRC校验
