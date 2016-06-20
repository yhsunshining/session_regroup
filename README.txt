本项目根据输入的pcap文件，提供TCP,UDP以及HTTP协议的解析功能。
输出3中格式的文件，其中.pcap为分割的TCP/UDP会话文件，-.txt为TCP/UDP/HTTP会话五元组控制信息结构体文件，.txt为TCP负载文件，/file目录下为HTTP实体文件。

本项目为免安装版本，可直接运行。适用于Windows X64机器。使用zlib进行解压缩操作，因此需要依赖zlib1.dll，请确保文件运行目录或system32文件夹下存在该文件。

./Release目录下包含可执行文件以及dll库，./Release/test目录下包含提供的待测pcap文件。