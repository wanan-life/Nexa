# Nexa bundled tools

Nexa 默认只从本目录解析外部工具，不依赖系统 PATH，也不通过环境变量指定工具路径。

期望结构：

```text
tools/
  subfinder/
    subfinder
  httpx/
    httpx
  OneForAll/
    oneforall.py
    requirements.txt
```

查看安装状态：

```bash
nexa tools
```

初始化工具：

```bash
python scripts/bootstrap_tools.py
```

当前 bootstrap 脚本面向 macOS arm64：

- subfinder: `v2.14.0`
- httpx: `v1.9.0`
- OneForAll: `https://github.com/shmilylty/OneForAll.git`

OneForAll 的依赖较旧，脚本会优先创建 `tools/OneForAll/.venv` 并安装 `requirements.txt`。如果依赖安装失败，Nexa 仍然可以使用 subfinder 和 httpx，OneForAll 会在扫描 summary 中显示失败原因。

