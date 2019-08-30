# redis-sniffer
> redis sniffer network traffic 

###
* 支持query 命令解析
* 支持RESP 协议解析
* 支持状态回复（status reply）解析
* 支持错误回复（error reply）解析
* 支持整数回复（integer reply）解析
* 支持批量回复（bulk reply）解析
* 支持多条批量回复（multi bulk reply）解析

### Usage
```
Copyright by jige003

Usage:
    redissniffer [-h] -i interface -p port
```

### 日志
```
[*] sniffe on interface: lo
2019-08-30 16:34:40  127.0.0.1:55676 -> 127.0.0.1:6379 [ req ]  keys *
2019-08-30 16:34:40  127.0.0.1:6379 -> 127.0.0.1:55676 [ resp ]  hello xx bar counter foo mylist
2019-08-30 16:34:44  127.0.0.1:55676 -> 127.0.0.1:6379 [ req ]  get hello
2019-08-30 16:34:44  127.0.0.1:6379 -> 127.0.0.1:55676 [ resp ]  dfdkjfkdjkfdjkfj
2019-08-30 16:34:45  127.0.0.1:55676 -> 127.0.0.1:6379 [ req ]  xxx
2019-08-30 16:34:45  127.0.0.1:6379 -> 127.0.0.1:55676 [ resp ]  ERR unknown command 'xxx'
```

### 参考文档
http://redisdoc.com/topic/protocol.html
