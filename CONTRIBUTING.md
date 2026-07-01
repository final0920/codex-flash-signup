# 贡献指南

感谢你对 Mongoose Svelte 的关注！以下是参与贡献的流程和规范。

## 开发环境

1. Fork 本仓库并克隆到本地
2. 安装依赖：
   - GCC（支持 C11）
   - libcurl 开发库
   - SQLite3 开发库
   - Node.js 18+
   - Python 3
3. 编译项目：`make`
4. 运行开发模式：`make run`

## 提交流程

1. 基于 `main` 分支创建功能分支：`git checkout -b feature/your-feature`
2. 进行修改并确保编译通过
3. 提交代码，commit message 使用中文，格式参考现有提交历史
4. 推送分支并创建 Pull Request

## 代码规范

### C 代码

- 使用 C11 标准（`-std=gnu11`）
- 缩进使用 4 空格
- 函数命名使用 `snake_case`
- 结构体和类型命名使用 `snake_case_t`
- 头文件使用 `#pragma once` 或 include guard

### 前端代码

- 使用 TypeScript
- 组件文件使用 PascalCase 命名
- 遵循 Svelte 官方风格指南

## Pull Request 规范

- PR 标题简明扼要，描述本次变更的核心内容
- 如果涉及 UI 变更，请附上截图
- 确保不引入编译警告
- 新功能需要在 PR 描述中说明使用方式

## Issue 规范

- Bug 报告请提供：操作系统、编译器版本、复现步骤和错误日志
- 功能建议请描述使用场景和期望行为

## 许可证

提交代码即表示你同意将贡献的代码以 AGPL-3.0 许可证发布。
