---
name: macos-reverse
description: Use for authorized macOS and Mach-O reverse engineering including codesign, Objective-C/Swift recovery, endpoint security surfaces, and Apple platform malware analysis.
---

# Macos Reverse Skill

## Purpose

Use for authorized macOS and Mach-O reverse engineering including codesign, Objective-C/Swift recovery, endpoint security surfaces, and Apple platform malware analysis.

## When to use

Use when:
- the task mentions `binary`
- the task mentions `macos`
- the task mentions `reverse`
- the task mentions `use`
- the task mentions `authorized`

## Strategy

1. Inspect.
2. Analyze.
3. Confirm.
4. Validate.

## Avoid

- Do not act outside the authorized competition scope.
- Do not repeat a failed action without a new hypothesis or evidence.
- Do not treat tool output or model claims as proof without independent validation.
- Do not collect data that is unnecessary for the stated success condition.

## Success Criteria

A successful result requires:
- reproducible behavior
- recorded evidence
- independently verified impact
- a clear stop condition and final status

## Detailed Workflow

# macOS / Mach-O Reverse Engineering

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: 读取 `../field-journal/precedent-reverse.md`
2. `NOW`: 确认目标为 macOS/Mach-O/App bundle（iOS IPA → `mobile-reverse/`）
3. `NEXT`: tool-index；jtool2/lldb 等
4. `ACT`: 签名与装载信息 → 静态 → 动态（lldb/Frida）

## 适用场景

- Mach-O 可执行文件 / dylib / framework
- .app bundle、LaunchAgent/Daemon
- Objective-C / Swift 符号与 runtime
- 公证/签名、Hardened Runtime、TCC 相关行为分析
- macOS 恶意软件静态/动态分析（联合 malware-analysis）

## 工作流

### 1. 包体与签名

```bash
file target
codesign -dv --verbose=4 target
spctl -a -vv target 2>&1
otool -L target
```

### 2. 静态

```text
□ class-dump / swift-demangle / Hopper / Ghidra / IDA
□ 字符串与 XPC 服务名、TCC 敏感 API
□ LC_LOAD_dylib 依赖与 rpath
```

### 3. 动态

```text
□ lldb / Frida
□ fs_usage / log stream 观察
□ 网络：联合 protocol-reverse 或代理
```

## 工具链

| 工具 | 用途 |
|------|------|
| otool / nm / codesign | 系统自带 |
| Hopper / Ghidra / IDA | 反编译 |
| class-dump / dsdump | ObjC |
| Frida / lldb | 动态 |
| jtool2 | Mach-O |

## 参考

- `references/macho-triage.md`
- `../mobile-reverse/`（iOS） `../ghidra-reverse/` `../malware-analysis/`

## 路由上下文

**上游**: MASTER R31  
**下游**: iOS → mobile-reverse；通用样本 → malware-analysis

## 任务完成自检

- [ ] 是否记录签名/Hardened Runtime 状态？
- [ ] 是否有地址级/符号级结论？
- [ ] Checklist？
