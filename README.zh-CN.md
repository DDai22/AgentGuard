# AgentGuard（中文说明）

AgentGuard 是面向 Codex、Claude Code、Gemini CLI、Aider、Cursor Agent、Cline、Goose 及自定义编程 Agent 的本地、只读观测工具。它记录进程、文件、网络、系统和资源元数据，不代理流量、不读取文件内容、不修改或阻断 Agent。

## 启动

```powershell
python -m pip install -e .
python -m agentguard discover
python -m agentguard ui --root D:\path\to\workspace
```

英文界面：

```powershell
python -m agentguard ui --root D:\path\to\workspace --language en
```

也可以指定其他 Agent 进程：

```powershell
python -m agentguard ui --targets my-agent.exe --language en
```

点击操作可查看完整元数据，包括会话归属、对话 ID（可用时）、文件路径、读写量、网络字节数和速率。详细能力、限制和开发说明请参阅 [English README](README.md)。
