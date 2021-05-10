# FridaUnpack

- DexFiledumpDex.js
    - 来对抗整体型壳,dump时机点较早,为DexFile::DexFile 和 DexFile::OpenCommon,此时还没有类进行初始化 无法对抗抽取壳
    - 使用方法 frida -U -f com.xxx.xxx -l DexFileDumpDex.js --no-pause 等待dex进行dump, 可以手动操作,来dump更多的dex
    - 默认dump到sdcard中, 需要赋予app sd卡读写权限 如果没有 可以自行修改路径保存到app的私有目录下
    
- ClassLinkerDumpDex.js
    - 需要将lib目录下的fart(64).so 放到/data/app这个目录再chmod 777 fart*.so 
    - 一定程度上对抗抽取壳,可以使用spwan和attach模式
        - frida -U -f com.xxx.xxx -l DexFileDumpDex.js --no-pause 
        - frida -FU -l DexFileDumpDex.js
    - 手动运行fart(),会枚举所有Classloader调用loadclass加载所有类,等待类加载完毕后会自动dump dex
    - 也可以单独dump一个类 使用dumpclass这个api传入类名
    - 默认dump到sdcard中, 需要赋予app sd卡读写权限 如果没有 可以自行修改路径保存到app的私有目录下
    
- 注意: android8运行fart()主动调用loadclass可能会崩溃,这种情况下可以试试android7,会稳定一点,
但是android7不支持hookLinkCode 可以手动注释.
  
- 脚本只测试过androi7.1.2和android8.1.0两个版本 其他版本自行实验修改