AntV npm 投毒自检

```
usage: antv_scan.py [-h] [--deep] [--include-global] [--json FILE] [path]

AntV npm 投毒事件 (Mini Shai-Hulud, 2026-05-19) 本地检测

positional arguments:
  path              扫描根目录, 默认当前目录

options:
  -h, --help        show this help message and exit
  --deep            对所有包做 C2 字符串扫描 (慢)
  --include-global  同时扫描全局 npm 安装目录
  --json FILE       将结果写入 JSON 文件

```

及 AntV npm 投毒应急响应方案

