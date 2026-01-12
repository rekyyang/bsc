# OpcodeCompiler 代码逻辑详细分析

本文档对 `opcodeCompiler` 模块进行函数级别的详细分析，涵盖所有核心文件和函数。

---

## 目录

1. [基础模块](#基础模块)
   - [evmByteCode.go](#evmbytecodego)
   - [opCodeCache.go](#opcodecachego)
   - [opCodeProcessor.go](#opcodeprocessorgo)
2. [MIR 核心模块](#mir-核心模块)
   - [MIR.go](#mirgo)
   - [ValueStack.go](#valuestackgo)
   - [MIROperations.go](#miroperationsgo)
3. [MIR 基本块模块](#mir-基本块模块)
   - [MIRBasicBlock.go](#mirbasicblockgo)
4. [CFG 构建模块](#cfg-构建模块)
   - [opcodeParser.go](#opcodeparsergo)
5. [MIR 解释器模块](#mir-解释器模块)
   - [MIRInterpreter.go](#mirinterpretergo)
6. [后端接口模块](#后端接口模块)
   - [state_backend.go](#state_backendgo)
   - [call_create_backend.go](#call_create_backendgo)
   - [statedb_backend.go](#statedb_backendgo)
   - [evm_callcreate_backend.go](#evm_callcreate_backendgo)
   - [evm_runner.go](#evm_runnergo)
7. [可视化模块](#可视化模块)
   - [cfg_viz.go](#cfg_vizgo)

---

## 基础模块

### evmByteCode.go

**文件作用**: 定义所有 EVM 字节码常量，包括算术、比较、加密、存储、控制流等操作码。

**主要常量定义**:
- `0x0` 范围: 算术操作 (STOP, ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND)
- `0x10` 范围: 比较操作 (LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR)
- `0x20` 范围: 加密操作 (KECCAK256)
- `0x30` 范围: 闭包状态操作 (ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY, GASPRICE, EXTCODESIZE, EXTCODECOPY, RETURNDATASIZE, RETURNDATACOPY, EXTCODEHASH)
- `0x40` 范围: 区块操作 (BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, BLOBHASH, BLOBBASEFEE)
- `0x50` 范围: 存储和执行 (POP, MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, JUMP, JUMPI, PC, MSIZE, GAS, JUMPDEST, TLOAD, TSTORE, MCOPY, PUSH0)
- `0x60-0x7f` 范围: PUSH 操作 (PUSH1 到 PUSH32)
- `0x80-0x8f` 范围: DUP 操作 (DUP1 到 DUP16)
- `0x90-0x9f` 范围: SWAP 操作 (SWAP1 到 SWAP16)
- `0xa0-0xa4` 范围: 日志操作 (LOG0 到 LOG4)
- `0xb0-0xcf` 范围: 自定义优化指令 (Nop, AndSwap1PopSwap2Swap1, Swap2Swap1PopJump 等)
- `0xd0-0xd3` 范围: EOF 操作 (DATALOAD, DATALOADN, DATASIZE, DATACOPY)
- `0xe0-0xee` 范围: EOF 操作 (RJUMP, RJUMPI, RJUMPV, CALLF, RETF, JUMPF, DUPN, SWAPN, EXCHANGE, EOFCREATE, RETURNCONTRACT)
- `0xf0-0xff` 范围: 闭包操作 (CREATE, CALL, CALLCODE, RETURN, DELEGATECALL, CREATE2, RETURNDATALOAD, EXTCALL, EXTDELEGATECALL, STATICCALL, EXTSTATICCALL, REVERT, INVALID, SELFDESTRUCT)

**无函数定义，仅常量声明**

---

### opCodeCache.go

**文件作用**: 提供操作码优化结果的缓存管理，使用 LRU 缓存存储优化后的代码和位向量。

#### 类型定义

**OpCodeCache**
```go
type OpCodeCache struct {
    optimizedCodeCache *lru.Cache[common.Hash, []byte]  // 优化后的代码缓存
    bitvecCache        *lru.Cache[common.Hash, []byte]  // 位向量缓存
}
```

#### 函数分析

**GetCachedBitvec(codeHash common.Hash) []byte**
- **功能**: 从缓存中获取指定代码哈希的位向量
- **参数**: `codeHash` - 代码哈希值
- **返回**: 位向量字节数组，如果不存在则返回 nil
- **逻辑**: 调用 `bitvecCache.Get(codeHash)` 获取缓存值

**AddBitvecCache(codeHash common.Hash, bitvec []byte)**
- **功能**: 将位向量添加到缓存中
- **参数**: 
  - `codeHash` - 代码哈希值
  - `bitvec` - 位向量字节数组
- **逻辑**: 调用 `bitvecCache.Add(codeHash, bitvec)` 添加到缓存

**RemoveCachedCode(hash common.Hash)**
- **功能**: 从缓存中移除指定哈希的优化代码
- **参数**: `hash` - 代码哈希值
- **逻辑**: 调用 `optimizedCodeCache.Remove(hash)` 移除缓存项

**GetCachedCode(hash common.Hash) []byte**
- **功能**: 从缓存中获取指定哈希的优化代码
- **参数**: `hash` - 代码哈希值
- **返回**: 优化后的代码字节数组，如果不存在则返回 nil
- **逻辑**: 调用 `optimizedCodeCache.Get(hash)` 获取缓存值

**AddCodeCache(hash common.Hash, optimizedCode []byte)**
- **功能**: 将优化后的代码添加到缓存中
- **参数**: 
  - `hash` - 代码哈希值
  - `optimizedCode` - 优化后的代码字节数组
- **逻辑**: 调用 `optimizedCodeCache.Add(hash, optimizedCode)` 添加到缓存

**getOpCodeCacheInstance() *OpCodeCache**
- **功能**: 获取全局的 OpCodeCache 单例实例
- **返回**: OpCodeCache 实例指针
- **逻辑**: 返回包级变量 `opcodeCache`

**init()**
- **功能**: 初始化全局缓存实例
- **逻辑**: 
  - 创建 `OpCodeCache` 实例
  - 初始化 `optimizedCodeCache` (容量: 128 * 1024)
  - 初始化 `bitvecCache` (容量: 128 * 1024)

---

### opCodeProcessor.go

**文件作用**: 提供操作码优化处理的核心逻辑，包括操作码融合、基本块生成和模式匹配。

#### 类型定义

**OpCodeProcessorConfig**
```go
type OpCodeProcessorConfig struct {
    DoOpcodeFusion bool  // 是否执行操作码融合
}
```

**optimizeTaskType**
```go
type optimizeTaskType byte
const (
    generate optimizeTaskType = 1  // 生成优化代码任务
    flush    optimizeTaskType = 2  // 刷新缓存任务
)
```

**optimizeTask**
```go
type optimizeTask struct {
    taskType optimizeTaskType  // 任务类型
    hash     common.Hash       // 代码哈希
    rawCode  []byte            // 原始代码
}
```

**BasicBlock**
```go
type BasicBlock struct {
    StartPC    uint64   // 基本块起始 PC
    EndPC      uint64   // 基本块结束 PC (不包含)
    Opcodes    []byte   // 基本块中的操作码
    JumpTarget *uint64  // 如果基本块以跳转结束，目标 PC
    IsJumpDest bool     // 基本块是否以 JUMPDEST 开始
}
```

#### 函数分析

**EnableOptimization()**
- **功能**: 启用操作码优化功能
- **逻辑**: 设置全局变量 `enabled = true`

**DisableOptimization()**
- **功能**: 禁用操作码优化功能
- **逻辑**: 设置全局变量 `enabled = false`

**IsEnabled() bool**
- **功能**: 检查操作码优化是否启用
- **返回**: 如果启用返回 true，否则返回 false

**LoadOptimizedCode(hash common.Hash) []byte**
- **功能**: 从缓存加载优化后的代码
- **参数**: `hash` - 代码哈希值
- **返回**: 优化后的代码，如果未启用或不存在则返回 nil
- **逻辑**: 
  - 检查是否启用优化
  - 从缓存获取优化代码

**LoadBitvec(codeHash common.Hash) []byte**
- **功能**: 从缓存加载位向量
- **参数**: `codeHash` - 代码哈希值
- **返回**: 位向量，如果未启用或不存在则返回 nil
- **逻辑**: 
  - 检查是否启用优化
  - 从缓存获取位向量

**StoreBitvec(codeHash common.Hash, bitvec []byte)**
- **功能**: 将位向量存储到缓存
- **参数**: 
  - `codeHash` - 代码哈希值
  - `bitvec` - 位向量
- **逻辑**: 
  - 检查是否启用优化
  - 添加到缓存

**GenOrLoadOptimizedCode(hash common.Hash, code []byte)**
- **功能**: 异步生成或加载优化代码
- **参数**: 
  - `hash` - 代码哈希值
  - `code` - 原始代码
- **逻辑**: 
  - 检查是否启用优化
  - 创建生成任务并发送到任务通道

**taskProcessor()**
- **功能**: 后台任务处理器，从任务通道接收任务并处理
- **逻辑**: 
  - 无限循环从 `taskChannel` 接收任务
  - 调用 `handleOptimizationTask` 处理任务

**handleOptimizationTask(task optimizeTask)**
- **功能**: 处理优化任务
- **参数**: `task` - 优化任务
- **逻辑**: 
  - 根据任务类型分发:
    - `generate`: 调用 `TryGenerateOptimizedCode`
    - `flush`: 调用 `DeleteCodeCache`

**GenOrRewriteOptimizedCode(hash common.Hash, code []byte) ([]byte, error)**
- **功能**: 生成或重写优化代码并刷新缓存
- **参数**: 
  - `hash` - 代码哈希值
  - `code` - 原始代码
- **返回**: 优化后的代码和错误
- **逻辑**: 
  - 检查是否启用优化
  - 调用 `processByteCodes` 处理代码
  - 将结果添加到缓存
  - 返回优化代码

**TryGenerateOptimizedCode(hash common.Hash, code []byte) ([]byte, error)**
- **功能**: 尝试生成优化代码，如果缓存中存在则直接返回
- **参数**: 
  - `hash` - 代码哈希值
  - `code` - 原始代码
- **返回**: 优化后的代码和错误
- **逻辑**: 
  - 先尝试从缓存获取
  - 如果不存在，调用 `GenOrRewriteOptimizedCode` 生成

**DeleteCodeCache(hash common.Hash)**
- **功能**: 删除指定哈希的代码缓存
- **参数**: `hash` - 代码哈希值
- **逻辑**: 
  - 检查是否启用优化
  - 从缓存移除

**processByteCodes(code []byte) ([]byte, error)**
- **功能**: 处理字节码，执行优化
- **参数**: `code` - 原始字节码
- **返回**: 优化后的代码和错误
- **逻辑**: 调用 `DoCFGBasedOpcodeFusion` 执行基于 CFG 的操作码融合

**DoCodeFusion(code []byte) ([]byte, error)**
- **功能**: 执行代码融合的导出版本，用于基准测试和外部测试
- **参数**: `code` - 原始字节码
- **返回**: 优化后的代码和错误
- **逻辑**: 调用 `DoCFGBasedOpcodeFusion`

**DoCFGBasedOpcodeFusion(code []byte) ([]byte, error)**
- **功能**: 在基本块内执行操作码融合，跳过 "others" 类型的块
- **参数**: `code` - 原始字节码
- **返回**: 优化后的代码和错误
- **逻辑**: 
  1. 调用 `GenerateBasicBlocks` 生成基本块
  2. 创建原始代码的副本
  3. 遍历每个基本块:
     - 获取块类型，跳过 "others" 类型
     - 检查是否包含已优化的操作码，如果有则返回错误
     - 检查是否包含 INVALID 操作码，如果有则跳过
     - 调用 `fuseBlock` 对块执行融合
  4. 返回融合后的代码

**fuseBlock(code []byte, block BasicBlock) error**
- **功能**: 对单个基本块应用操作码融合
- **参数**: 
  - `code` - 代码字节数组（会被修改）
  - `block` - 要融合的基本块
- **返回**: 错误（如果有）
- **逻辑**: 
  1. 从 `block.StartPC` 到 `block.EndPC` 遍历
  2. 对每个位置调用 `applyFusionPatterns` 应用融合模式
  3. 根据跳过的步数更新索引
  4. 处理 PUSH 指令的数据字节

**applyFusionPatterns(code []byte, cur int, endPC int) int**
- **功能**: 应用已知的融合模式，返回要跳过的步数
- **参数**: 
  - `code` - 代码字节数组
  - `cur` - 当前位置
  - `endPC` - 基本块结束位置
- **返回**: 要跳过的步数（如果匹配到模式），否则返回 0
- **逻辑**: 
  - 按模式长度从大到小检查（15字节、12字节、9字节、7字节、5字节、4字节、3字节、2字节、1字节）
  - 每个模式检查特定的操作码序列
  - 如果匹配，将第一个操作码替换为融合操作码，其他位置替换为 NOP
  - 返回匹配模式的长度

**getBlockType(block BasicBlock, blocks []BasicBlock, blockIndex int) string**
- **功能**: 根据内容对基本块进行分类
- **参数**: 
  - `block` - 要分类的基本块
  - `blocks` - 所有基本块数组
  - `blockIndex` - 当前块的索引
- **返回**: 块类型字符串 ("Empty", "entryBB", "JumpDest", "conditional fallthrough", "others")
- **逻辑**: 
  1. 如果操作码为空，返回 "Empty"
  2. 如果 StartPC 为 0，返回 "entryBB"
  3. 如果以 JUMPDEST 开始，返回 "JumpDest"
  4. 如果前一个块以 JUMPI 结束，返回 "conditional fallthrough"
  5. 否则返回 "others"

**calculateSkipSteps(code []byte, cur int) (skip bool, steps int)**
- **功能**: 计算当前位置需要跳过的步数（用于 PUSH 指令）
- **参数**: 
  - `code` - 代码字节数组
  - `cur` - 当前位置
- **返回**: 是否需要跳过和跳过的步数
- **逻辑**: 
  - 如果是 PUSH1-PUSH32，计算数据字节数
  - 如果是优化的操作码（Push2Jump, Push2JumpI 等），返回相应的步数
  - 否则返回 false, 0

**GenerateBasicBlocks(code []byte) []BasicBlock**
- **功能**: 从字节码数组生成基本块数组
- **参数**: `code` - 字节码数组
- **返回**: 基本块数组
- **逻辑**: 
  1. 第一遍扫描: 识别所有 JUMPDEST 位置
  2. 第二遍扫描: 构建基本块
     - 在 JUMPDEST 或 INVALID 处开始新块
     - 计算指令长度（考虑 PUSH 数据）
     - 在块终止符（STOP, RETURN, REVERT, JUMP, JUMPI 等）处结束块
  3. 返回所有基本块

**isBlockTerminator(op ByteCode) bool**
- **功能**: 检查操作码是否是基本块终止符
- **参数**: `op` - 操作码
- **返回**: 如果是终止符返回 true
- **逻辑**: 
  - 检查是否为 STOP, RETURN, REVERT, SELFDESTRUCT
  - 检查是否为 JUMP, JUMPI
  - 检查是否为 RJUMP, RJUMPI, RJUMPV
  - 检查是否为 CALLF, RETF, JUMPF

---

## MIR 核心模块

### MIR.go

**文件作用**: 定义 MIR（Mid-level Intermediate Representation）指令的核心数据结构和方法。

#### 类型定义

**mirDefKey**
```go
type mirDefKey struct {
    defBlockNum   uint          // 定义所在的块编号
    evmPC         uint          // EVM 程序计数器
    op            MirOperation  // MIR 操作
    phiStackIndex int           // PHI 节点的栈槽索引
}
```

**MIR**
```go
type MIR struct {
    op            MirOperation    // MIR 操作码
    operands      []*Value        // 操作数（SSA 值）
    meta          []byte          // 元数据
    pc            *uint           // 原始指令的程序计数器（可选）
    idx           int             // 在基本块中的索引
    resIdx        int             // 全局结果槽索引
    defBlockNum   uint            // 稳定标识的定义块编号
    evmPC         uint            // 原始 EVM 操作码的字节偏移
    evmOp         byte            // 原始 EVM 操作码字节值
    evmOpIndex    int             // EVM 操作码流中的索引
    aux           *MIR            // 可选的辅助 MIR
    phiStackIndex int             // PHI 节点的栈槽索引
    opKinds       []byte          // 操作数类型预编码 (0=const, 1=def, 2=fallback)
    opConst       []*uint256.Int  // 常量操作数的预编码值
    opDefIdx      []int           // 定义操作数的索引
    genStackDepth int             // 生成时的栈深度
}
```

#### 函数分析

**keyForDef(def *MIR) mirDefKey**
- **功能**: 为 MIR 定义生成稳定的键，用于跨块重建的映射
- **参数**: `def` - MIR 定义指针
- **返回**: `mirDefKey` 结构
- **逻辑**: 
  - 如果 def 为 nil，返回空的 mirDefKey
  - 否则返回包含 defBlockNum, evmPC, op, phiStackIndex 的键

**Op() MirOperation**
- **功能**: 返回 MIR 指令的操作码
- **返回**: MIR 操作码，如果 MIR 为 nil 则返回 MirINVALID

**EvmPC() uint**
- **功能**: 返回原始 EVM 程序计数器
- **返回**: EVM PC，如果 MIR 为 nil 则返回 0

**EvmOp() byte**
- **功能**: 返回原始 EVM 操作码字节
- **返回**: EVM 操作码，如果 MIR 为 nil 则返回 0

**newVoidMIR(operation MirOperation) *MIR**
- **功能**: 创建无操作数的 MIR 指令
- **参数**: `operation` - MIR 操作码
- **返回**: 新的 MIR 指针
- **逻辑**: 
  - 创建新的 MIR 结构
  - 设置操作码
  - 操作数列表为 nil

**newNopMIR(operation MirOperation, original_opnds []*Value) *MIR**
- **功能**: 创建 NOP MIR 指令（用于优化）
- **参数**: 
  - `operation` - 原始操作码
  - `original_opnds` - 原始操作数
- **返回**: 新的 MIR 指针，操作码为 MirNOP
- **逻辑**: 
  - 创建新的 MIR 结构
  - 设置操作码为 MirNOP
  - 保存原始操作数
  - 在 meta 中保存原始操作码

**newUnaryOpMIR(operation MirOperation, opnd *Value, stack *ValueStack) *MIR**
- **功能**: 创建一元操作 MIR 指令
- **参数**: 
  - `operation` - MIR 操作码
  - `opnd` - 操作数
  - `stack` - 值栈（未使用）
- **返回**: 新的 MIR 指针
- **逻辑**: 
  - 创建新的 MIR 结构
  - 设置操作码和操作数
  - 将 MIR 添加到操作数的使用列表
  - 如果操作数是跨块 live-in，标记相关信息

**newBinaryOpMIR(operation MirOperation, opnd1 *Value, opnd2 *Value, stack *ValueStack) *MIR**
- **功能**: 创建二元操作 MIR 指令
- **参数**: 
  - `operation` - MIR 操作码
  - `opnd1` - 第一个操作数
  - `opnd2` - 第二个操作数
  - `stack` - 值栈（未使用）
- **返回**: 新的 MIR 指针
- **逻辑**: 
  - 创建新的 MIR 结构
  - 设置操作码和两个操作数
  - 将 MIR 添加到两个操作数的使用列表
  - 如果操作数是跨块 live-in，标记相关信息

**newTernaryOpMIR(operation MirOperation, opnd1 *Value, opnd2 *Value, opnd3 *Value, stack *ValueStack) *MIR**
- **功能**: 创建三元操作 MIR 指令
- **参数**: 
  - `operation` - MIR 操作码
  - `opnd1` - 第一个操作数
  - `opnd2` - 第二个操作数
  - `opnd3` - 第三个操作数
  - `stack` - 值栈（未使用）
- **返回**: 新的 MIR 指针
- **逻辑**: 
  - 创建新的 MIR 结构
  - 设置操作码和三个操作数
  - 将 MIR 添加到三个操作数的使用列表

**Result() *Value**
- **功能**: 返回 MIR 指令产生的结果值
- **返回**: Value 指针，如果操作是 MirNOP 则返回 nil
- **逻辑**: 
  - 如果操作是 MirNOP，返回 nil
  - 否则创建新的 Variable 类型的 Value，def 指向当前 MIR

---

### ValueStack.go

**文件作用**: 定义值栈（ValueStack）和值（Value）的数据结构，用于模拟 EVM 栈操作。

#### 类型定义

**ValueKind**
```go
type ValueKind int
const (
    Konst     ValueKind = 0 + iota  // 常量
    Arguments                        // 输入参数
    Variable                         // 运行时确定的值
    Unknown                          // 非法值
)
```

**Value**
```go
type Value struct {
    kind    ValueKind  // 值类型
    def     *MIR       // 定义该值的 MIR 指令
    use     []*MIR     // 使用该值的 MIR 指令列表
    payload []byte     // 原始字节数据
    u       *uint256.Int  // 预解码的常量值（用于 Konst）
    liveIn  bool       // 标记该值来自父基本块
}
```

**ValueStack**
```go
type ValueStack struct {
    data []Value  // 栈数据
}
```

#### 函数分析

**push(ptr *Value)**
- **功能**: 将值推入栈顶
- **参数**: `ptr` - 要推入的值指针
- **逻辑**: 
  - 如果 ptr 为 nil，直接返回
  - 否则将值追加到 data 切片

**pop() Value**
- **功能**: 从栈顶弹出值
- **返回**: 弹出的值，如果栈为空则返回 Unknown 类型的值
- **逻辑**: 
  - 如果栈为空，返回默认的 Unknown 值
  - 否则取出最后一个元素并移除

**size() int**
- **功能**: 返回栈的大小
- **返回**: 栈中元素的数量

**peek(n int) *Value**
- **功能**: 返回栈顶第 n 个元素的指针（0 索引，0 是栈顶）
- **参数**: `n` - 从栈顶开始的索引
- **返回**: 值的指针，如果索引无效则返回 nil
- **逻辑**: 
  - 检查索引有效性
  - 计算实际数组索引（栈从右到左增长，栈顶在末尾）
  - 返回对应元素的指针

**swap(i, j int)**
- **功能**: 交换栈中位置 i 和 j 的元素（从栈顶开始索引）
- **参数**: 
  - `i` - 第一个位置索引
  - `j` - 第二个位置索引
- **逻辑**: 
  - 检查索引有效性
  - 转换为实际数组索引
  - 交换两个元素

**newValue(kind ValueKind, def *MIR, use *MIR, payload []byte) *Value**
- **功能**: 创建新的值
- **参数**: 
  - `kind` - 值类型
  - `def` - 定义该值的 MIR
  - `use` - 使用该值的 MIR（可选）
  - `payload` - 原始字节数据
- **返回**: 新的 Value 指针
- **逻辑**: 
  - 创建新的 Value 结构
  - 设置类型和定义
  - 如果提供了 use，添加到使用列表
  - 如果是常量类型，预解码为 uint256.Int

**clone() []Value**
- **功能**: 返回栈值的深拷贝
- **返回**: 值的切片副本
- **逻辑**: 
  - 如果栈为空，返回 nil
  - 否则创建新切片并复制所有值

**resetTo(snapshot []Value)**
- **功能**: 将当前栈重置为提供的快照
- **参数**: `snapshot` - 要恢复的快照
- **逻辑**: 
  - 如果快照为 nil，清空栈
  - 否则创建新切片并复制快照内容

**markAllLiveIn()**
- **功能**: 将栈上所有值标记为 live-in（来自父基本块）
- **逻辑**: 遍历所有值，设置 liveIn 标志为 true

**IsConst() bool**
- **功能**: 检查值是否为常量
- **返回**: 如果是常量返回 true

**ConstValue() uint64**
- **功能**: 返回常量值作为 uint64
- **返回**: 常量值，如果不是常量则返回 0
- **逻辑**: 
  - 检查是否为常量
  - 从 payload 字节解码为 uint64（小端序）

**Equal(other *Value) bool**
- **功能**: 检查两个值是否相等
- **参数**: `other` - 要比较的另一个值
- **返回**: 如果相等返回 true
- **逻辑**: 
  - 比较类型
  - 如果是常量，比较数值（不是字节）
  - 否则比较 def 指针

**DebugString() string**
- **功能**: 返回值的调试字符串表示
- **返回**: 人类可读的字符串
- **逻辑**: 
  - 如果是 nil，返回 "nil"
  - 如果是常量，返回 "const:0x" + 十六进制值
  - 如果是参数，返回 "arg"
  - 如果是变量，返回 "var@<idx>"
  - 否则返回 "unknown"

---

### MIROperations.go

**文件作用**: 定义所有 MIR 操作码常量和字符串表示。

#### 常量定义

MIR 操作码常量按功能分类：
- **算术操作**: MirADD, MirMUL, MirSUB, MirDIV, MirSDIV, MirMOD, MirSMOD, MirADDMOD, MirMULMOD, MirEXP, MirSIGNEXT
- **比较操作**: MirLT, MirGT, MirSLT, MirSGT, MirEQ, MirISZERO
- **位操作**: MirAND, MirOR, MirXOR, MirNOT, MirBYTE, MirSHL, MirSHR, MirSAR
- **加密操作**: MirKECCAK256
- **环境信息**: MirADDRESS, MirBALANCE, MirORIGIN, MirCALLER, MirCALLVALUE, MirCALLDATALOAD, MirCALLDATASIZE, MirCALLDATACOPY, MirCODESIZE, MirCODECOPY, MirGASPRICE, MirEXTCODESIZE, MirEXTCODECOPY, MirRETURNDATASIZE, MirRETURNDATACOPY, MirEXTCODEHASH
- **区块信息**: MirBLOCKHASH, MirCOINBASE, MirTIMESTAMP, MirNUMBER, MirDIFFICULTY, MirGASLIMIT, MirCHAINID, MirSELFBALANCE, MirBASEFEE, MirBLOBHASH, MirBLOBBASEFEE
- **栈操作**: MirPOP, MirDUP1-MirDUP16, MirSWAP1-MirSWAP16
- **内存操作**: MirMLOAD, MirMSTORE, MirMSTORE8, MirMSIZE, MirMCOPY
- **存储操作**: MirSLOAD, MirSSTORE, MirTLOAD, MirTSTORE
- **控制流**: MirJUMP, MirJUMPI, MirPC, MirGAS, MirJUMPDEST, MirPHI
- **日志操作**: MirLOG0-MirLOG4
- **系统调用**: MirCREATE, MirCALL, MirCALLCODE, MirRETURN, MirDELEGATECALL, MirCREATE2, MirREVERT, MirSELFDESTRUCT, MirINVALID, MirSTOP
- **EOF 操作**: MirDATALOAD, MirDATALOADN, MirDATASIZE, MirDATACOPY
- **其他**: MirNOP

#### 函数分析

**String() string**
- **功能**: 返回 MIR 操作码的人类可读名称
- **返回**: 操作码名称字符串
- **逻辑**: 使用 switch 语句返回对应的字符串表示

---

## MIR 基本块模块

### MIRBasicBlock.go

**文件作用**: 定义 MIR 基本块的数据结构和相关操作，包括 MIR 指令创建、常量折叠、PHI 节点处理等。

#### 类型定义

**MIRBasicBlock**
```go
type MIRBasicBlock struct {
    blockNum        uint                      // 块编号
    firstPC         uint                     // 起始 PC
    lastPC          uint                     // 结束 PC
    initDepth       int                      // 初始栈深度
    instructions    []*MIR                   // MIR 指令列表
    parents         []*MIRBasicBlock          // 父块列表
    children        []*MIRBasicBlock          // 子块列表
    parentsBitmap   *bitmap                   // 父块位图（用于快速查找）
    childrenBitmap  *bitmap                  // 子块位图
    entryStack      []Value                  // 入口栈快照
    exitStack       []Value                  // 出口栈快照
    incomingStacks  map[*MIRBasicBlock][]Value  // 来自每个父块的入口栈
    liveOutDefs     []*MIR                   // 出口处活跃的定义
    built           bool                     // 是否已构建
    queued          bool                     // 是否在队列中
    unresolvedJump  bool                     // 是否有未解析的跳转
    pos             int                      // 执行时的指令位置
    evmOpCounts     map[byte]uint32          // EVM 操作码计数
    emittedOpCounts map[byte]uint32          // 已发射的操作码计数
    evmOps          []evmOpAtPC              // EVM 操作码流
    evmPCToOpIndex  map[uint]int             // PC 到操作码索引的映射
}
```

#### 关键函数分析

**NewMIRBasicBlock(blockNum, pc uint) *MIRBasicBlock**
- **功能**: 创建新的 MIR 基本块
- **参数**: 
  - `blockNum` - 块编号
  - `pc` - 起始程序计数器
- **返回**: 新的 MIRBasicBlock 指针
- **逻辑**: 
  - 初始化所有字段
  - 创建空的指令列表、父块/子块列表
  - 初始化位图和映射

**appendMIR(mir *MIR) *MIR**
- **功能**: 将 MIR 指令追加到基本块
- **参数**: `mir` - 要追加的 MIR 指令
- **返回**: 追加后的 MIR 指针（可能被修改）
- **逻辑**: 
  1. 设置 MIR 的索引和定义块编号
  2. 附加 EVM 映射信息（evmPC, evmOp）
  3. 分配全局结果槽索引（resIdx）
  4. 预编码操作数信息（opKinds, opConst, opDefIdx）
  5. 追加到指令列表

**CreateUnaryOpMIR(op MirOperation, stack *ValueStack) *MIR**
- **功能**: 创建一元操作 MIR 指令
- **参数**: 
  - `op` - MIR 操作码
  - `stack` - 值栈
- **返回**: MIR 指针，如果被常量折叠则返回 nil
- **逻辑**: 
  1. 从栈弹出操作数
  2. 尝试常量折叠（MirNOT, MirISZERO）
  3. 如果折叠成功，将结果推回栈并返回 nil
  4. 否则创建 MIR 指令并追加
  5. 将结果推回栈

**CreateBinOpMIR(op MirOperation, stack *ValueStack) *MIR**
- **功能**: 创建二元操作 MIR 指令
- **参数**: 
  - `op` - MIR 操作码
  - `stack` - 值栈
- **返回**: MIR 指针，如果被常量折叠则返回 nil
- **逻辑**: 
  1. 从栈弹出两个操作数
  2. 尝试常量折叠
  3. 如果折叠成功，将结果推回栈并返回 nil
  4. 否则创建 MIR 指令并追加
  5. 将结果推回栈

**CreateTernaryOpMIR(op MirOperation, stack *ValueStack) *MIR**
- **功能**: 创建三元操作 MIR 指令
- **参数**: 
  - `op` - MIR 操作码
  - `stack` - 值栈
- **返回**: MIR 指针，如果被常量折叠则返回 nil
- **逻辑**: 
  1. 从栈弹出三个操作数（按 EVM 栈顺序）
  2. 尝试常量折叠
  3. 如果折叠成功，将结果推回栈并返回 nil
  4. 否则创建 MIR 指令并追加
  5. 将结果推回栈

**CreatePhiMIR(ops []*Value, stack *ValueStack, phiStackIndex int) *MIR**
- **功能**: 创建 PHI 节点，合并来自不同前驱的值
- **参数**: 
  - `ops` - 来自各个前驱的值列表
  - `stack` - 值栈
  - `phiStackIndex` - PHI 节点代表的栈槽索引（0 为栈顶）
- **返回**: 创建的 PHI MIR 指针
- **逻辑**: 
  1. 创建新的 MIR，操作码为 MirPHI
  2. 设置操作数为来自各个前驱的值
  3. 设置 phiStackIndex
  4. 将结果推回栈
  5. 追加到指令列表

**CreateDupMIR(n int, stack *ValueStack) *MIR**
- **功能**: 创建 DUP 操作（在栈上复制值）
- **参数**: 
  - `n` - 要复制的栈位置（1-indexed）
  - `stack` - 值栈
- **返回**: 始终返回 nil（DUP 不生成运行时 MIR）
- **逻辑**: 
  1. 检查栈深度是否足够
  2. 获取要复制的值
  3. 在栈上复制该值
  4. 不生成运行时 MIR（gas 通过每块操作码计数处理）

**CreateSwapMIR(n int, stack *ValueStack) *MIR**
- **功能**: 创建 SWAP 操作（交换栈上两个值）
- **参数**: 
  - `n` - 要交换的栈位置（1-indexed）
  - `stack` - 值栈
- **返回**: 始终返回 nil（SWAP 不生成运行时 MIR）
- **逻辑**: 
  1. 检查栈深度是否足够
  2. 在栈上交换值
  3. 不生成运行时 MIR（gas 通过每块操作码计数处理）

**GetNextOp() *MIR**
- **功能**: 获取基本块中的下一个 MIR 指令（用于执行）
- **返回**: 下一个 MIR 指针，如果没有更多指令则返回 nil
- **逻辑**: 
  1. 检查是否还有未执行的指令
  2. 返回当前位置的指令并递增位置计数器

**ResetForRebuild(preserveEntry bool)**
- **功能**: 清除临时构建产物，以便重新构建基本块
- **参数**: `preserveEntry` - 是否保留入口栈快照
- **逻辑**: 
  1. 清空指令列表和位置计数器
  2. 清空操作码计数和 EVM 操作码流
  3. 清空出口栈和活跃定义
  4. 根据参数决定是否保留入口栈

**tryConstFoldUnary(op MirOperation, aVal *Value) (*Value, bool)**
- **功能**: 尝试对一元操作进行常量折叠
- **参数**: 
  - `op` - MIR 操作码
  - `aVal` - 操作数值
- **返回**: 折叠后的常量值和是否成功
- **逻辑**: 
  - 检查操作数是否为常量
  - 对 MirNOT 和 MirISZERO 进行常量计算
  - 返回结果常量值

**tryConstFoldBinary(op MirOperation, aVal, bVal *Value) (*Value, bool)**
- **功能**: 尝试对二元操作进行常量折叠
- **参数**: 
  - `op` - MIR 操作码
  - `aVal, bVal` - 两个操作数值
- **返回**: 折叠后的常量值和是否成功
- **逻辑**: 
  - 检查两个操作数是否都是常量
  - 对算术、比较、位操作等进行常量计算
  - 返回结果常量值

**tryConstFoldTernary(op MirOperation, aVal, bVal, cVal *Value) (*Value, bool)**
- **功能**: 尝试对三元操作进行常量折叠
- **参数**: 
  - `op` - MIR 操作码
  - `aVal, bVal, cVal` - 三个操作数值
- **返回**: 折叠后的常量值和是否成功
- **逻辑**: 
  - 检查三个操作数是否都是常量
  - 对 ADDMOD 和 MULMOD 进行常量计算
  - 返回结果常量值

---

## CFG 构建模块

### opcodeParser.go

**文件作用**: 实现从 EVM 字节码构建控制流图（CFG）的核心逻辑，包括基本块构建、PHI 节点插入、边连接等。

#### 类型定义

**CFG**
```go
type CFG struct {
    codeAddr        common.Hash              // 代码地址哈希
    rawCode         []byte                   // 原始字节码
    basicBlocks     []*MIRBasicBlock         // 所有基本块
    basicBlockCount uint                     // 基本块计数
    nextResIdx      int                      // 下一个结果槽索引
    defKeyToResIdx  map[mirDefKey]int        // 定义键到结果索引的映射
    pcToBlock       map[uint]*MIRBasicBlock  // PC 到基本块的映射
    jumpDests       map[uint]bool            // 有效的 JUMPDEST 位置
}
```

**CFGNonConvergentError**
```go
type CFGNonConvergentError struct {
    Builds    int          // 构建次数
    MaxBuilds int         // 最大构建次数
    CodeHash  common.Hash // 代码哈希
    CodeLen   int         // 代码长度
}
```

#### 关键函数分析

**NewCFG(hash common.Hash, code []byte) *CFG**
- **功能**: 创建新的 CFG
- **参数**: 
  - `hash` - 代码哈希
  - `code` - 原始字节码
- **返回**: 新的 CFG 指针
- **逻辑**: 
  - 初始化所有字段
  - 创建空的映射和切片

**Parse() error**
- **功能**: 从原始字节码构建控制流图
- **返回**: 错误（如果有）
- **逻辑**: 
  1. 识别所有有效的 JUMPDEST 位置
  2. 创建入口块（PC=0）
  3. 使用工作列表算法处理块:
     - 从队列取出块
     - 如果已构建则跳过
     - 调用 `buildBasicBlock` 构建块
     - 将子块加入队列
  4. 设置最大构建次数限制（防止无限循环）
  5. 返回构建错误（如果有）

**buildBasicBlock(block *MIRBasicBlock, validJumpDests map[uint]bool) error**
- **功能**: 构建单个基本块，将 EVM 操作码转换为 MIR 指令
- **参数**: 
  - `block` - 要构建的基本块
  - `validJumpDests` - 有效的 JUMPDEST 位置映射
- **返回**: 错误（如果有）
- **逻辑**: 
  1. 获取块的入口栈
  2. 从 firstPC 开始遍历字节码:
     - 检查基本块边界（JUMPDEST）
     - 记录 EVM 操作码计数
     - 根据操作码类型分发处理:
       - 栈操作（PUSH, DUP, SWAP, POP）
       - 一元操作（NOT, ISZERO）
       - 二元操作（ADD, MUL, SUB 等）
       - 三元操作（ADDMOD, MULMOD）
       - 内存操作（MLOAD, MSTORE, MSTORE8, MSIZE, MCOPY）
       - 存储操作（SLOAD, SSTORE, TLOAD, TSTORE）
       - 区块信息操作（ADDRESS, BALANCE 等）
       - 区块操作（BLOCKHASH, COINBASE 等）
       - 日志操作（LOG0-LOG4）
       - 系统调用（CALL, CREATE 等）
       - 控制流（JUMP, JUMPI, STOP, RETURN, REVERT 等）
  3. 在块终止符处结束块并记录出口栈

**getEntryStackForBlock(block *MIRBasicBlock) *ValueStack**
- **功能**: 确定基本块的初始栈状态
- **参数**: `block` - 基本块
- **返回**: 值栈指针
- **逻辑**: 
  1. **情况 1**: 入口块（无前驱）
     - 返回空栈
  2. **情况 2**: 首次访问或入口栈无效
     - 收集所有前驱的出口栈快照
     - 使用众数策略选择栈高度（处理不同栈高度的情况）
     - 对每个栈槽位置:
       - 如果所有前驱的值相同，直接使用
       - 否则创建 PHI 节点合并
     - 设置入口栈快照
  3. **情况 3**: 重新访问（已有入口栈快照）
     - 从快照实例化工作栈

**connectEdge(parent, child *MIRBasicBlock, exitSnapshot []Value)**
- **功能**: 连接父块到子块，记录入口栈快照
- **参数**: 
  - `parent` - 父块
  - `child` - 子块
  - `exitSnapshot` - 父块的出口栈快照
- **逻辑**: 
  1. 在父块的子块列表中添加子块（如果不存在）
  2. 在子块的父块列表中添加父块（如果不存在）
  3. 如果入口栈快照发生变化:
     - 更新子块的 incomingStacks
     - 使子块的入口栈无效
     - 标记子块需要重建
     - 标记所有后代需要重建

**scanJumpDests() map[uint]bool**
- **功能**: 扫描字节码，识别所有有效的 JUMPDEST 位置
- **返回**: JUMPDEST 位置到布尔值的映射
- **逻辑**: 
  1. 遍历所有字节码
  2. 如果是 JUMPDEST，标记位置
  3. 如果是 PUSH 指令，跳过数据字节
  4. 其他指令，前进 1 字节

**handleStackOp(block *MIRBasicBlock, op compiler.ByteCode, stack *ValueStack, pc uint) (uint, error)**
- **功能**: 处理栈操作（PUSH, DUP, SWAP, POP）
- **参数**: 
  - `block` - 基本块
  - `op` - EVM 操作码
  - `stack` - 值栈
  - `pc` - 当前程序计数器
- **返回**: 新的 PC 和错误
- **逻辑**: 
  - PUSH: 读取数据字节，创建常量值，推入栈
  - DUP: 调用 CreateDupMIR
  - SWAP: 调用 CreateSwapMIR
  - POP: 从栈弹出值（不生成 MIR）

---

## MIR 解释器模块

### MIRInterpreter.go

**文件作用**: 实现 MIR 指令的解释执行，包括操作数求值、gas 计费、内存管理、状态访问等。

#### 类型定义

**MIRInterpreter**
```go
type MIRInterpreter struct {
    cfg                *CFG                   // 控制流图
    results            []uint256.Int          // 结果表（按 resIdx 索引）
    resultsGen         []uint32               // 结果生成标记
    gen                uint32                 // 当前生成号
    mem                []byte                 // 线性内存模型
    validJumpDests     map[uint]bool          // 有效跳转目标
    chainRules         params.Rules           // 链规则
    gasLimit           uint64                 // Gas 限制
    gasUsed            uint64                 // 已使用 Gas
    contractAddr       common.Address         // 合约地址
    callerAddr         common.Address         // 调用者地址
    callValue          *uint256.Int           // 调用值
    state              StateBackend           // 状态后端
    callData           []byte                 // 调用数据
    returnData         []byte                 // 返回数据
    callCreate         CallCreateBackend      // 调用创建后端
    blockNumber        uint64                 // 区块号
    blockTime          uint64                 // 区块时间
    blockCoinbase      common.Address         // 区块矿工地址
    // ... 更多字段
}
```

**ExecResult**
```go
type ExecResult struct {
    HaltOp      MirOperation  // 停止操作
    ReturnData  []byte        // 返回数据
    Err         error         // 错误
    GasUsed     uint64        // 已使用 Gas
    GasLeft     uint64        // 剩余 Gas
    RefundUsed  uint64        // 已使用的退款
    LastEVMPC   uint          // 最后执行的 EVM PC
    ReturnOffset uint64       // RETURN 偏移
    ReturnSize   uint64       // RETURN 大小
}
```

#### 关键函数分析

**NewMIRInterpreter(cfg *CFG) *MIRInterpreter**
- **功能**: 创建新的 MIR 解释器
- **参数**: `cfg` - 控制流图
- **返回**: 新的解释器指针
- **逻辑**: 
  - 初始化所有字段
  - 创建结果表和内存
  - 设置默认值

**Run() ExecResult**
- **功能**: 从标准入口点（PC=0）执行
- **返回**: 执行结果
- **逻辑**: 调用 `RunFrom(0)`

**RunFrom(entryPC uint) ExecResult**
- **功能**: 从指定 PC 开始执行
- **参数**: `entryPC` - 入口程序计数器
- **返回**: 执行结果
- **逻辑**: 
  1. 获取入口基本块
  2. 循环执行基本块:
     - 重置块的指令位置
     - 检查是否需要重建块（动态跳转）
     - 如果块未构建，构建它
     - 执行块中的指令:
       - 计算常量 gas
       - 根据操作码类型执行相应逻辑
       - 处理控制流（JUMP, JUMPI, STOP, RETURN 等）
     - 移动到下一个块
  3. 处理执行结果和错误

**evalOperand(m *MIR, idx int) (*uint256.Int, error)**
- **功能**: 求值 MIR 指令的操作数
- **参数**: 
  - `m` - MIR 指令
  - `idx` - 操作数索引
- **返回**: 操作数值和错误
- **逻辑**: 
  1. 检查操作数类型（使用预编码的 opKinds）
  2. 如果是常量（opKinds[idx] == 0），返回预编码的常量值
  3. 如果是变量（opKinds[idx] == 1），从结果表获取值
  4. 否则递归求值操作数的定义

**evalBinary(m *MIR) (*uint256.Int, *uint256.Int, error)**
- **功能**: 求值二元操作的两个操作数
- **参数**: `m` - MIR 指令
- **返回**: 两个操作数值和错误
- **逻辑**: 
  - 调用 `evalOperand` 获取两个操作数
  - 返回结果

**evalUnary(m *MIR) (*uint256.Int, error)**
- **功能**: 求值一元操作的操作数
- **参数**: `m` - MIR 指令
- **返回**: 操作数值和错误
- **逻辑**: 
  - 调用 `evalOperand` 获取操作数
  - 返回结果

**evalPhi(cur, prev *MIRBasicBlock, m *MIR) (*uint256.Int, error)**
- **功能**: 求值 PHI 节点，根据前驱块选择对应的值
- **参数**: 
  - `cur` - 当前基本块
  - `prev` - 前一个基本块
  - `m` - PHI MIR 指令
- **返回**: PHI 结果值和错误
- **逻辑**: 
  1. 获取当前块的 incomingStacks
  2. 找到前驱块对应的入口栈快照
  3. 根据 phiStackIndex 从快照中获取值
  4. 求值该值并返回

**chargeGas(amount uint64) error**
- **功能**: 扣除 Gas
- **参数**: `amount` - 要扣除的 Gas 数量
- **返回**: 错误（如果 Gas 不足）
- **逻辑**: 
  - 增加 gasUsed
  - 如果超过 gasLimit，返回错误

**ensureMem(size int)**
- **功能**: 确保内存至少有指定大小
- **参数**: `size` - 所需内存大小
- **逻辑**: 
  - 如果当前内存小于所需大小，扩展内存
  - 新分配的内存初始化为 0

**resultSlot(m *MIR) *uint256.Int**
- **功能**: 获取 MIR 指令的结果槽
- **参数**: `m` - MIR 指令
- **返回**: 结果槽指针
- **逻辑**: 
  - 根据 resIdx 从结果表获取槽
  - 如果槽不存在或属于旧生成，分配新槽
  - 标记为当前生成

---

## 后端接口模块

### state_backend.go

**文件作用**: 定义状态后端接口和内存实现，用于 SLOAD/SSTORE gas 计费和状态访问。

#### 接口定义

**StateBackend**
```go
type StateBackend interface {
    GetBalance(addr common.Address) common.Hash
    GetBalanceU256(addr common.Address) *uint256.Int
    SetBalanceU256(addr common.Address, amount *uint256.Int)
    AddBalanceU256(addr common.Address, amount *uint256.Int)
    SubBalanceU256(addr common.Address, amount *uint256.Int)
    GetCode(addr common.Address) []byte
    GetCodeHash(addr common.Address) common.Hash
    GetCodeSize(addr common.Address) int
    Exists(addr common.Address) bool
    Empty(addr common.Address) bool
    HasSelfDestructed(addr common.Address) bool
    SelfDestruct(addr common.Address)
    GetState(addr common.Address, slot common.Hash) common.Hash
    GetCommittedState(addr common.Address, slot common.Hash) common.Hash
    SetState(addr common.Address, slot common.Hash, value common.Hash)
    AddRefund(gas uint64)
    SubRefund(gas uint64)
    GetRefund() uint64
    AddressInAccessList(addr common.Address) bool
    SlotInAccessList(addr common.Address, slot common.Hash) (bool, bool)
    AddAddressToAccessList(addr common.Address)
    AddSlotToAccessList(addr common.Address, slot common.Hash)
    AddLog(addr common.Address, topics []common.Hash, data []byte, blockNumber uint64)
    Snapshot() int
    RevertToSnapshot(id int)
}
```

#### 实现

**InMemoryState**: 内存中的状态实现，用于测试和工具。

---

### call_create_backend.go

**文件作用**: 定义调用和创建后端接口，用于处理 CALL*/CREATE* 操作码。

#### 接口定义

**CallCreateBackend**
```go
type CallCreateBackend interface {
    Call(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, returnGas uint64, err error)
    CallCode(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, returnGas uint64, err error)
    DelegateCall(caller, addr, to common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, returnGas uint64, err error)
    StaticCall(caller, to common.Address, input []byte, gas uint64) (ret []byte, returnGas uint64, err error)
    Create(caller common.Address, initCode []byte, gas uint64, value *uint256.Int) (ret []byte, addr common.Address, returnGas uint64, err error)
    Create2(caller common.Address, initCode []byte, gas uint64, value *uint256.Int, salt *uint256.Int) (ret []byte, addr common.Address, returnGas uint64, err error)
}
```

**NoopCallCreateBackend**: 空操作实现，用于测试。

---

### statedb_backend.go

**文件作用**: 将 geth 的 vm.StateDB 适配到 MIR 的 StateBackend 接口。

**StateDBBackend**: 适配器实现，将所有调用转发到 vm.StateDB。

---

### evm_callcreate_backend.go

**文件作用**: 将 geth 的 vm.EVM 适配到 MIR 的 CallCreateBackend 接口。

**EVMCallCreateBackend**: 适配器实现，将所有调用转发到 vm.EVM。

---

### evm_runner.go

**文件作用**: 将 MIRInterpreter 适配到 vm.ContractRunner 接口，使 MIR 可以在 geth 的 EVM 中使用。

#### 类型定义

**EVMRunner**
```go
type EVMRunner struct {
    evm                *vm.EVM
    cfgCache           map[common.Hash]*CFG
    itPool             sync.Pool
    stateBackend       StateDBBackend
    callBackend        EVMCallCreateBackend
    blockNumber        uint64
    chainRules         params.Rules
    mirStepHook        func(evmPC uint, evmOp byte, op MirOperation)
    mirStepHookFactory func(it *MIRInterpreter) func(evmPC uint, evmOp byte, op MirOperation)
}
```

#### 关键函数分析

**NewEVMRunner(evm *vm.EVM) *EVMRunner**
- **功能**: 创建新的 EVM 运行器
- **参数**: `evm` - EVM 实例
- **返回**: 新的运行器指针
- **逻辑**: 
  - 初始化所有字段
  - 创建解释器池
  - 设置后端适配器
  - 缓存链规则和区块上下文

**Run(contract *vm.Contract, input []byte, readOnly bool) ([]byte, error)**
- **功能**: 运行合约代码
- **参数**: 
  - `contract` - 合约
  - `input` - 输入数据
  - `readOnly` - 是否只读
- **返回**: 返回数据和错误
- **逻辑**: 
  1. 从缓存获取或构建 CFG
  2. 从池中获取解释器实例
  3. 配置解释器（gas、状态后端、调用后端等）
  4. 设置区块上下文和调用上下文
  5. 执行解释器
  6. 返回结果

---

## 可视化模块

### cfg_viz.go

**文件作用**: 提供 CFG 的 Graphviz DOT 格式可视化功能。

#### 函数分析

**ToDot() string**
- **功能**: 返回 CFG 的 Graphviz DOT 表示
- **返回**: DOT 格式字符串
- **逻辑**: 
  1. 创建 DOT 图头部
  2. 遍历所有基本块:
     - 生成节点标签（包含块 ID、PC 范围、栈高度）
     - 添加指令信息（限制显示数量）
     - 生成边（从块到子块）
  3. 返回完整的 DOT 字符串

---

## 总结

本文档详细分析了 `opcodeCompiler` 模块的所有核心组件，从基础的操作码定义到高级的 MIR 解释执行，涵盖了：

1. **基础模块**: 操作码定义、缓存管理、代码优化
2. **MIR 核心**: MIR 指令结构、值栈、操作码定义
3. **基本块**: MIR 基本块构建、常量折叠、PHI 节点
4. **CFG 构建**: 从字节码构建控制流图、边连接、入口栈计算
5. **解释执行**: MIR 指令执行、gas 计费、内存管理
6. **后端接口**: 状态访问、调用创建、EVM 集成
7. **可视化**: CFG 图形化表示

整个系统实现了从 EVM 字节码到 MIR 中间表示的转换，以及 MIR 的高效执行，为 EVM 代码分析和优化提供了强大的基础设施。

