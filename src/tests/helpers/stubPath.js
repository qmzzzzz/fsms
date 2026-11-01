'use strict';

/**
 * 让孩子 shell 真正用上「PATH 桩」目录
 *
 * 问题：MSYS/Git Bash 启动时会把 /mingw64/bin:/usr/bin:/c/<user>/bin **前置**到自己看到的
 * PATH 上（实测：传进去的 PATH 无论是 Windows 形态还是 POSIX 形态，`command -v gpg` 都先
 * 命中 /usr/bin/gpg——Git for Windows 自带 gnupg）。于是「把桩目录塞进 PATH 最前」这套在
 * Linux 上成立的注入方式，在 Windows 上对**与 MSYS 自带工具同名**的桩（gpg 就是）会静默
 * 失效：真二进制被执行，用例报的是真二进制的错，看起来像被测脚本的缺陷。
 *
 * 解法：在**孩子 shell 内部**赋值 PATH——bash 起来之后 MSYS 不会再前置自己的目录，
 * 「桩在前」这才真的成立（同文件里那条"PATH 指向不存在的目录 ⇒ 判 REJECTED"的用例，
 * 用的就是这个机制：bash 内 PATH 一改，/usr/bin 里的 gpg 就看不见了）。
 * Linux 上同一段前缀只是把同一个目录再放一遍，行为不变：单一代码路径、不做平台分支，
 * 避免"两个平台跑的是两套夹具"。
 */

/** Windows 驱动器路径 → MSYS 形态（C:\a\b → /c/a/b）；本来就是 POSIX 的原样返回 */
function toPosixPath(p) {
  const s = String(p).replace(/\\/g, '/');
  return /^[A-Za-z]:\//.test(s) ? `/${s[0].toLowerCase()}${s.slice(2)}` : s;
}

/** 拼在脚本最前面：把 stubDir 放到孩子 shell 的 PATH 最前 */
function stubPathPreamble(stubDir) {
  return `PATH='${toPosixPath(stubDir)}':"$PATH"; export PATH; `;
}

/**
 * 把「bash <脚本> <参数…>」这一调用形态包成「先在 shell 内收口 PATH，再 exec 同一个脚本」，
 * 不改脚本、不改参数表，argv 形状与原来逐字一致。
 */
function execThroughStubPath(scriptPath, args, stubDir, shell = 'bash') {
  return {
    file: shell,
    // 三种写法各有各的坑，实测（Git Bash 5.3.9 / MSYS）：
    //   · `exec "$@"`（直接 exec 脚本文件）——依赖**可执行位**。本仓 scripts/*.sh 在 git 里
    //     全是 100644；MSYS 下照样能跑（shell 自己读文件），Linux 下 execve 直接 EACCES，
    //     非交互 shell 随即退出 ⇒ 两个备份套件会在 CI 上整片假红。
    //   · `exec "$0"`（exec 回 shell 本体）——在 Windows 上 $0 是 `…/Git/bin/bash.exe`，
    //     重新起一个 **Windows 进程**会让 MSYS 再走一遍启动注入，把 /mingw64/bin:/usr/bin
    //     塞回 PATH 最前面：桩目录被顶到后面，`date` 命中 /usr/bin/date（实测 PATH 首项
    //     变成 /mingw64/bin，用例报的是真日期）——夹具静默失效，比假红更坏。
    //   · `exec bash …`（**按 PATH 解析**到 /usr/bin/bash 这个 MSYS 本体）——不重走启动注入，
    //     桩目录保持第一，且走解释器、与可执行位无关。两个平台的语义因此一致。
    // $0 只是占位标签（'stub-path'）；脚本路径作为 $1 交给 bash。
    args: ['-c', `${stubPathPreamble(stubDir)}exec bash "$@"`, 'stub-path', scriptPath, ...args],
  };
}

module.exports = { toPosixPath, stubPathPreamble, execThroughStubPath };
