# 致谢

这里记录改变过这个项目的人与项目，以及他们贡献了什么。README 只列简短名单，细节放在这一页。

[English](ACKNOWLEDGEMENTS.md) · **简体中文**

## 贡献者

目前还没有外部 issue 报告者或代码贡献者。当一份报告改变了项目，报告者会连同 issue/PR 链接与它带来的变化一起列在这里。

## 架构与研究启发

- **bla** —— counter-REA 防盾概念（canary、预算消耗、影子逻辑）。
- **py-ocsf-models** —— 类型化 OCSF 模型。
- **sigma-cli / pySigma** —— Sigma 规则生成。
- **CrowdSec** —— detector / decider / bouncer 解耦。

umbra-sentry 的全部实现均为原创；没有从这些项目复制源码。

## 安全参考

- **OWASP MASTG** —— Android 反逆向防御与“没有 100% 防护”的框架。
- **Check Point Research, Anti-Debug Tricks** —— Windows 反调试技术分类。
- **al-khaser** —— 用于交叉检查覆盖面的反调试/反 VM 测试目录。

这些参考影响了威胁模型与测试用例；它们不是内置依赖。
