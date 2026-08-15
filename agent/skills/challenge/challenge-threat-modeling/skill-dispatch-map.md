# Skill 调度映射表

> 挑战Agent在威胁建模中发现漏洞类型后，通过此映射表确定应该让执行Agent加载哪个skill。
> 在下发任务时，在提示词中指定 `skill: {skill_name}`。

## Web 漏洞 → 执行Agent Skill

| 漏洞类型 | 执行Skill | 路径 |
|---------|----------|------|
| SQL注入 | sqli_sql_injection | executor-agent/web/sqli_sql_injection/ |
| NoSQL注入 | sqli_sql_injection | executor-agent/web/sqli_sql_injection/ |
| SSRF | offensive_ssrf | executor-agent/web/offensive_ssrf/ |
| SSTI / 模板注入 | offensive_ssti | executor-agent/web/offensive_ssti/ |
| XSS / 跨站脚本 | offensive_xss | executor-agent/web/offensive_xss/ |
| XXE / XML实体注入 | offensive_xxe | executor-agent/web/offensive_xxe/ |
| 反序列化 | deserialization_insecure | executor-agent/web/deserialization_insecure/ |
| HTTP请求走私 | request_smuggling | executor-agent/web/request_smuggling/ |
| 原型链污染 | prototype_pollution | executor-agent/web/prototype_pollution/ |
| JWT攻击 | offensive_jwt | executor-agent/web/offensive_jwt/ |
| OAuth攻击 | offensive_oauth | executor-agent/web/offensive_oauth/ |
| GraphQL安全 | offensive_graphql | executor-agent/web/offensive_graphql/ |
| IDOR / 越权 | offensive_idor | executor-agent/web/offensive_idor/ |
| 路径遍历 / LFI | path_traversal_lfi | executor-agent/web/path_traversal_lfi/ |
| 命令注入 | offensive_ssti | executor-agent/web/offensive_ssti/ (参考RCE部分) |
| CRLF注入 | request_smuggling | executor-agent/web/request_smuggling/ |
| 开放重定向 | offensive_ssrf | executor-agent/web/offensive_ssrf/ (参考重定向链部分) |
| CSRF | offensive_oauth | executor-agent/web/offensive_oauth/ (参考CSRF部分) |
| 文件上传 | path_traversal_lfi | executor-agent/web/path_traversal_lfi/ (参考文件操作) |
| 信息收集 | src_hunter | challenge-agent/web/src_hunter/ (挑战Agent自用) |

## 二进制漏洞 → 执行Agent Skill

| 漏洞类型 | 执行Skill | 路径 |
|---------|----------|------|
| 栈溢出 | stack_overflow_and_rop | executor-agent/binary/stack_overflow_and_rop/ |
| ROP利用 | stack_overflow_and_rop | executor-agent/binary/stack_overflow_and_rop/ |
| 堆利用 (UAF/Double Free/Heap Overflow) | heap_exploitation | executor-agent/binary/heap_exploitation/ |
| 格式化字符串 | format_string_exploitation | executor-agent/binary/format_string_exploitation/ |
| 内核漏洞 | kernel_exploitation | executor-agent/binary/kernel_exploitation/ |
| 浏览器/V8利用 | browser_exploitation_v8 | executor-agent/binary/browser_exploitation_v8/ |
| 整数溢出 | ctf_pwn | executor-agent/binary/ctf_pwn/ |
| CTF综合PWN | ctf_pwn | executor-agent/binary/ctf_pwn/ |
| Fuzzing / 漏洞挖掘 | offensive_fuzzing | executor-agent/binary/offensive_fuzzing/ |
| 符号执行 | symbolic_execution_tools | executor-agent/binary/symbolic_execution_tools/ |
| Shellcode开发 | offensive_shellcode | executor-agent/binary/offensive_shellcode/ |
| 补丁差分/N-day | patch_diff_exploit | executor-agent/binary/patch_diff_exploit/ |
| 综合利用开发 | offensive_exploit_development | executor-agent/binary/offensive_exploit_development/ |
| 崩溃分析 | offensive_crash_analysis | executor-agent/binary/offensive_crash_analysis/ |
| 基础利用 | offensive_basic_exploitation | executor-agent/binary/offensive_basic_exploitation/ |
| 工程化利用链 | pwn_chain | executor-agent/binary/pwn_chain/ |

### 逆向分析工具

| 分析场景 | 执行Skill | 路径 |
|---------|----------|------|
| IDA Pro分析 | ida_reverse | executor-agent/binary/ida_reverse/ |
| Ghidra分析 | ghidra_reverse | executor-agent/binary/ghidra_reverse/ |
| radare2分析 | radare2 | executor-agent/binary/radare2/ |
| 恶意软件分析 | malware_analysis | executor-agent/binary/malware_analysis/ |
| Android APK逆向 | apk_reverse | executor-agent/binary/apk_reverse/ |
| .NET逆向 | dotnet_reverse | executor-agent/binary/dotnet_reverse/ |
| Go/Rust逆向 | go_rust_reverse | executor-agent/binary/go_rust_reverse/ |
| macOS逆向 | macos_reverse | executor-agent/binary/macos_reverse/ |
| 移动端逆向 | mobile_reverse | executor-agent/binary/mobile_reverse/ |
| 固件/IoT分析 | firmware_pentest | executor-agent/binary/firmware_pentest/ |
| 协议逆向 | protocol_reverse | executor-agent/binary/protocol_reverse/ |
| DSL/VM逆向 | dsl_vm_reverse | executor-agent/binary/dsl_vm_reverse/ |
| 字节码VM逆向 | vm_and_bytecode_reverse | executor-agent/binary/vm_and_bytecode_reverse/ |
| 二进制差分 | binary_diff | executor-agent/binary/binary_diff/ |

## AI漏洞 → 执行Agent Skill

| 漏洞类型 | 执行Skill | 路径 |
|---------|----------|------|
| Prompt Injection (自动化) | orchestrating_llm_attacks_with_pyrit | executor-agent/ai/orchestrating_llm_attacks_with_pyrit/ |
| RAG管道注入测试 | testing_prompt_injection_in_rag_pipelines | executor-agent/ai/testing_prompt_injection_in_rag_pipelines/ |
| 越狱/Jailbreak | orchestrating_llm_attacks_with_pyrit | executor-agent/ai/orchestrating_llm_attacks_with_pyrit/ |

## 区块链漏洞 → 执行Agent Skill

> 区块链方向当前无独立执行Agent skill。挑战Agent在分派任务时，直接在提示词中描述利用方法（如"构造重入攻击交易调用withdraw()"），由执行Agent按通用方式执行。如需链上交互，执行Agent可使用Foundry cast / web3.py等工具。

## 使用方式

挑战Agent在威胁建模中确定漏洞类型后：

1. 查此表找到对应的执行Agent skill
2. 在下发任务提示词中指定：
   ```
   skill: {skill_name}
   skill_path: executor-agent/{direction}/{skill_name}/
   ```
3. 执行Agent加载指定skill后按skill指南执行渗透操作

## 无匹配skill时的处理

如果漏洞类型无对应执行Agent skill，挑战Agent应在提示词中亲自撰写详细的利用任务（包括漏洞类型、利用思路、payload方向、flag获取路径），确保执行Agent有足够信息完成渗透。