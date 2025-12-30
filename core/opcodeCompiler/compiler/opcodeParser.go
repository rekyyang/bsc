package compiler

import (
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// CanonicalDepth is the depth key used for canonical blocks in pcToVariants.
// This special value (-1) distinguishes canonical blocks from variant blocks
// which use actual stack depths (>= 0) as keys.
// This is part of "Scheme A" - merging pcToBlock into pcToVariants.
const CanonicalDepth = -1

// scanForBlockStarts scans the bytecode to identify all potential basic block start PCs.
// Block starts are: PC 0, JUMPDESTs, and instructions immediately following terminators or branches.
// Also creates the MIRBasicBlock stub for each start PC.
func (c *CFG) preScanBlocks() error {
	// Ensure entry block exists
	if !c.hasBlockAtPC(0) {
		c.createBB(0, nil)
	}

	code := c.rawCode
	i := 0
	for i < len(code) {
		op := ByteCode(code[i])

		// JUMPDEST is always a block start
		if op == JUMPDEST {
			if !c.hasBlockAtPC(uint(i)) {
				c.createBB(uint(i), nil)
			}
		}

		// If previous instruction was a terminator or branch, this is a block start
		// (handled by the look-ahead below)

		// Check if current op causes the NEXT op to be a block start
		var nextPC int
		isTerminatorOrBranch := false

		if op >= PUSH1 && op <= PUSH32 {
			size := int(op - PUSH1 + 1)
			nextPC = i + 1 + size
		} else {
			nextPC = i + 1

			if op == STOP || op == RETURN || op == REVERT || op == INVALID || op == SELFDESTRUCT {
				isTerminatorOrBranch = true
			} else if op == JUMP || op == JUMPI {
				isTerminatorOrBranch = true
			}
		}

		if isTerminatorOrBranch && nextPC < len(code) {
			// The instruction following a terminator/branch is a block start (fallthrough or dead code entry)
			if !c.hasBlockAtPC(uint(nextPC)) {
				c.createBB(uint(nextPC), nil)
			}
		}

		i = nextPC
	}
	return nil
}

// tryResolveUint64ConstPC attempts to resolve a Value into a constant uint64 by
// recursively evaluating a small subset of MIR operations when all inputs are constants.
// This is used in the builder to conservatively identify PHI-derived JUMP/JUMPI targets.
// The evaluation is bounded by 'budget' to avoid pathological recursion.
func tryResolveUint64ConstPC(v *Value, budget int) (uint64, bool) {
	if v == nil || budget <= 0 {
		return 0, false
	}
	if v.kind == Konst {
		if v.u != nil {
			u, _ := v.u.Uint64WithOverflow()
			return u, true
		}
		// Fallback to payload
		tmp := uint256.NewInt(0).SetBytes(v.payload)
		u, _ := tmp.Uint64WithOverflow()
		return u, true
	}
	if v.kind != Variable || v.def == nil {
		return 0, false
	}
	// Helper to eval operand k
	evalOp := func(k int) (*uint256.Int, bool) {
		if k < 0 || k >= len(v.def.operands) || v.def.operands[k] == nil {
			return nil, false
		}
		if u64, ok := tryResolveUint64ConstPC(v.def.operands[k], budget-1); ok {
			return uint256.NewInt(0).SetUint64(u64), true
		}
		return nil, false
	}
	switch v.def.op {
	case MirPHI:
		// PHI itself is a constant only if all alternatives resolve to the same constant
		var have bool
		var out uint64
		for _, alt := range v.def.operands {
			if alt == nil {
				return 0, false
			}
			u, ok := tryResolveUint64ConstPC(alt, budget-1)
			if !ok {
				return 0, false
			}
			if !have {
				out = u
				have = true
			} else if out != u {
				return 0, false
			}
		}
		if have {
			return out, true
		}
		return 0, false
	case MirAND, MirOR, MirXOR, MirADD, MirSUB, MirSHL, MirSHR, MirSAR, MirBYTE:
		// Binary ops with constant operands
		a, okA := evalOp(0)
		b, okB := evalOp(1)
		if !okA || !okB {
			return 0, false
		}
		tmp := uint256.NewInt(0)
		switch v.def.op {
		case MirAND:
			tmp.And(a, b)
		case MirOR:
			tmp.Or(a, b)
		case MirXOR:
			tmp.Xor(a, b)
		case MirADD:
			tmp.Add(a, b)
		case MirSUB:
			tmp.Sub(a, b)
		case MirSHL:
			shift, _ := b.Uint64WithOverflow()
			tmp.Lsh(a, uint(shift))
		case MirSHR, MirSAR:
			shift, _ := b.Uint64WithOverflow()
			tmp.Rsh(a, uint(shift))
		case MirBYTE:
			// byte(n, x) extracts the nth byte from big-endian x (EVM semantics).
			n, _ := a.Uint64WithOverflow()
			if n >= 32 {
				tmp.Clear()
			} else {
				buf := a.Bytes32()
				// EVM byte index 0 = most significant byte
				byteVal := buf[n]
				tmp.SetUint64(uint64(byteVal))
			}
		}
		u, _ := tmp.Uint64WithOverflow()
		return u, true
	default:
		return 0, false
	}
}

// CFG is the IR record the control flow of the contract.
// It records not only the control flow info but also the state and memory accesses.
// CFG is mapping to <addr, code> pair, and there is no need to record CFG for every contract
// since it is just an IR, although the analyzing/compiling results are saved to the related cache.
type CFG struct {
	codeAddr        common.Hash
	rawCode         []byte
	basicBlocks     []*MIRBasicBlock
	basicBlockCount uint
	memoryAccessor  *MemoryAccessor
	stateAccessor   *StateAccessor
	// Fast lookup helpers, built on demand
	selectorIndex map[uint32]*MIRBasicBlock // 4-byte selector -> entry basic block
	// Scheme A: pcToVariants stores both canonical blocks (at CanonicalDepth=-1) and variant blocks (at actual depth)
	pcToVariants map[uint]map[int]*MIRBasicBlock // bytecode PC -> stack depth -> basic block
}

func NewCFG(hash common.Hash, code []byte) (c *CFG) {
	c = &CFG{}
	c.codeAddr = hash
	c.rawCode = code
	c.basicBlocks = []*MIRBasicBlock{}
	c.basicBlockCount = 0
	c.selectorIndex = nil
	// Scheme A: only pcToVariants needed (stores canonical at CanonicalDepth and variants at actual depth)
	c.pcToVariants = make(map[uint]map[int]*MIRBasicBlock)
	return c
}

// BlockByPC returns the basic block that owns the given EVM program counter, if known.
func (c *CFG) BlockByPC(pc uint) *MIRBasicBlock {
	if c == nil {
		return nil
	}
	return c.getBlockAtPC(pc)
}

// getBlockAtPC returns the canonical block at the given PC.
// Scheme A: reads from pcToVariants[pc][CanonicalDepth].
func (c *CFG) getBlockAtPC(pc uint) *MIRBasicBlock {
	if variants := c.pcToVariants[pc]; variants != nil {
		if bb, ok := variants[CanonicalDepth]; ok {
			return bb
		}
	}
	return nil
}

// hasBlockAtPC checks if there is a canonical block at the given PC.
func (c *CFG) hasBlockAtPC(pc uint) bool {
	return c.getBlockAtPC(pc) != nil
}

// getAllCanonicalBlocks returns all canonical blocks (from pcToVariants[CanonicalDepth]).
// Scheme A: iterates pcToVariants and collects blocks at CanonicalDepth.
func (c *CFG) getAllCanonicalBlocks() []*MIRBasicBlock {
	var blocks []*MIRBasicBlock
	for _, variants := range c.pcToVariants {
		if bb, ok := variants[CanonicalDepth]; ok && bb != nil {
			blocks = append(blocks, bb)
		}
	}
	return blocks
}

func (c *CFG) getMemoryAccessor() *MemoryAccessor {
	if c.memoryAccessor == nil {
		c.memoryAccessor = new(MemoryAccessor)
	}
	return c.memoryAccessor
}

func (c *CFG) getStateAccessor() *StateAccessor {
	if c.stateAccessor == nil {
		c.stateAccessor = new(StateAccessor)
	}
	return c.stateAccessor
}

// createEntryBB create an empty bb that contains (method/invoke) entry info.
func (c *CFG) createEntryBB() *MIRBasicBlock {
	entryBB := NewMIRBasicBlock(0, 0, nil)
	c.basicBlockCount++
	return entryBB
}

// createBB create a normal bb.
// Scheme A: writes to pcToVariants[pc][CanonicalDepth].
func (c *CFG) createBB(pc uint, parent *MIRBasicBlock) *MIRBasicBlock {
	// Check if already exists
	if existing := c.getBlockAtPC(pc); existing != nil {
		if parent != nil {
			existing.SetParents([]*MIRBasicBlock{parent})
		}
		return existing
	}

	bb := NewMIRBasicBlock(c.basicBlockCount, pc, parent)
	c.basicBlocks = append(c.basicBlocks, bb)
	c.basicBlockCount++

	// Scheme A: write to pcToVariants[pc][CanonicalDepth]
	if c.pcToVariants[pc] == nil {
		c.pcToVariants[pc] = make(map[int]*MIRBasicBlock)
	}
	c.pcToVariants[pc][CanonicalDepth] = bb

	return bb
}

// getVariantBlock retrieves or creates a basic block for a specific PC and stack depth.
// This handles stack polymorphism by creating variant blocks when stack heights differ.
// Scheme A compatible: uses getBlockAtPC instead of pcToBlock, handles CanonicalDepth.
func (c *CFG) getVariantBlock(pc uint, depth int, parent *MIRBasicBlock) *MIRBasicBlock {
	// Ensure canonical block exists (created by preScanBlocks)
	canonical := c.getBlockAtPC(pc)
	if canonical == nil {
		// Should have been created by preScanBlocks, but safe to create if missing
		canonical = c.createBB(pc, nil)
	}

	// Initialize variants map for this PC if needed
	if c.pcToVariants[pc] == nil {
		c.pcToVariants[pc] = make(map[int]*MIRBasicBlock)
	}

	// Check if a variant for this depth already exists
	if variant, found := c.pcToVariants[pc][depth]; found {
		if parent != nil {
			// Add parent linkage if not already present
			hasParent := false
			for _, p := range variant.Parents() {
				if p == parent {
					hasParent = true
					break
				}
			}
			if !hasParent {
				variant.SetParents(append(variant.Parents(), parent))
			}
		}
		return variant
	}

	// No variant for this depth yet.
	// Scheme A: Check if only CanonicalDepth exists (len == 1 with only CanonicalDepth entry).
	// If so, we can reuse the canonical block for this actual depth.
	// This ensures that for standard code (single stack height), we reuse the canonical block.
	onlyCanonicalExists := len(c.pcToVariants[pc]) == 1 && c.pcToVariants[pc][CanonicalDepth] != nil
	if onlyCanonicalExists {
		// Reuse canonical block: add reference at actual depth, keep CanonicalDepth as alias
		c.pcToVariants[pc][depth] = canonical
		canonical.SetInitDepth(depth)

		if parent != nil {
			// Add parent linkage
			hasParent := false
			for _, p := range canonical.Parents() {
				if p == parent {
					hasParent = true
					break
				}
			}
			if !hasParent {
				canonical.SetParents(append(canonical.Parents(), parent))
			}
		}
		return canonical
	}

	// Canonical is taken by another depth. Create a new variant block.
	// Create a new variant block (don't use createBB to avoid overwriting canonical)
	variant := NewMIRBasicBlock(c.basicBlockCount, pc, parent)
	c.basicBlocks = append(c.basicBlocks, variant)
	c.basicBlockCount++
	variant.SetInitDepth(depth)

	// Register variant
	c.pcToVariants[pc][depth] = variant

	// Debug log

	return variant
}

func (c *CFG) reachEndBB() {
}

// preScanBlocks performs a linear scan of the bytecode to identify all potential
// basic block boundaries (entry, jumpdests, and fallthroughs after terminators/branches).
// It pre-creates MIRBasicBlock stubs for them in pcToVariants[CanonicalDepth].
// (Redundant implementation removed)
// func (c *CFG) preScanBlocks() { ... }

// ==================== Core PHI Operations ====================

// linkPhiOperandsForBlock links PHI operands for a single block.
// Uses SortedParents() for deterministic ordering.
// This function is idempotent - it clears existing operands before relinking.
// Also populates phiPredDepth for stack-polymorphic PHI resolution.
func (cfg *CFG) linkPhiOperandsForBlock(bb *MIRBasicBlock) {
	if len(bb.Parents()) == 0 {
		return
	}

	// Collect PHI instructions
	phis := make(map[int]*MIR)
	for _, instr := range bb.Instructions() {
		if instr.op == MirPHI {
			phis[instr.phiStackIndex] = instr
		}
	}

	if len(phis) == 0 {
		return
	}

	// Clear existing operands and phiPredDepth (idempotent)
	for _, phi := range phis {
		phi.operands = nil
		phi.phiPredDepth = make(map[*MIRBasicBlock]int)
	}

	// Link operands using sorted parents for determinism
	sortedParents := bb.SortedParents()
	for _, parent := range sortedParents {
		ps := parent.ExitStack()
		exitDepth := 0
		if ps != nil {
			exitDepth = len(ps)
		}
		for idx, phi := range phis {
			var valPtr *Value
			if ps != nil {
				pos := len(ps) - 1 - idx
				if pos >= 0 && pos < len(ps) {
					val := ps[pos]
					v := val
					valPtr = &v
				}
			}
			// Original operands (position-based, for backward compatibility)
			phi.operands = append(phi.operands, valPtr)
			// Record exit stack depth for this predecessor (for stack-polymorphic resolution)
			// This allows runtime to compute the correct index even if stack depths differ
			phi.phiPredDepth[parent] = exitDepth
		}
	}
}

// simplifyPhiForBlock simplifies trivial PHIs in a single block.
// A PHI is trivial if all non-nil operands are equal.
func (cfg *CFG) simplifyPhiForBlock(bb *MIRBasicBlock) {
	for _, instr := range bb.Instructions() {
		if instr.op != MirPHI {
			continue
		}

		// Collect unique non-nil operands
		var uniqueOps []*Value
		for _, op := range instr.operands {
			if op == nil {
				continue
			}
			isDup := false
			for _, existing := range uniqueOps {
				if existing != nil && equalValueForFlow(op, existing) {
					isDup = true
					break
				}
			}
			if !isDup {
				uniqueOps = append(uniqueOps, op)
			}
		}

		// If only one unique non-nil operand, simplify PHI
		if len(uniqueOps) == 1 && uniqueOps[0] != nil {
			instr.operands = []*Value{uniqueOps[0]}
		}
	}
}

// resolvePhiJumpTargets resolves PHI-based JUMP/JUMPI targets for a block.
// Returns newly discovered target PCs that need to be built.
func (cfg *CFG) resolvePhiJumpTargets(bb *MIRBasicBlock) []uint64 {
	instrs := bb.Instructions()
	if len(instrs) == 0 {
		return nil
	}

	lastInst := instrs[len(instrs)-1]
	if lastInst.op != MirJUMP && lastInst.op != MirJUMPI {
		return nil
	}

	// Skip if already has children (resolved during build)
	if len(bb.Children()) > 0 {
		return nil
	}

	// Check if JUMP target is PHI-based
	if len(lastInst.operands) == 0 || lastInst.operands[0] == nil {
		return nil
	}

	d := lastInst.operands[0]
	if d.kind != Variable || d.def == nil || d.def.op != MirPHI {
		return nil
	}

	// Collect constant targets from PHI chain
	targetSet := make(map[uint64]bool)
	visited := make(map[*MIR]bool)

	var collectTargets func(*Value, int)
	collectTargets = func(v *Value, depth int) {
		if v == nil || depth > 32 {
			return
		}
		if v.kind == Konst {
			if v.payload != nil {
				var tpc uint64
				for _, b := range v.payload {
					tpc = (tpc << 8) | uint64(b)
				}
				targetSet[tpc] = true
			} else if v.u != nil {
				u, _ := v.u.Uint64WithOverflow()
				targetSet[u] = true
			}
			return
		}
		if v.kind == Variable && v.def != nil {
			if visited[v.def] {
				return
			}
			visited[v.def] = true
			if v.def.op == MirPHI {
				for _, op := range v.def.operands {
					collectTargets(op, depth+1)
				}
			} else {
				if tpc, ok := tryResolveUint64ConstPC(v, 16); ok {
					targetSet[tpc] = true
				}
			}
			return
		}
	}

	// Start from PHI operands
	for _, op := range d.def.operands {
		collectTargets(op, 0)
	}

	// Return discovered targets
	var targets []uint64
	for tpc := range targetSet {
		targets = append(targets, tpc)
	}
	return targets
}

// buildUnbuiltBlocks builds all blocks that have incoming stacks but aren't built yet.
// Returns the number of blocks built.
func (cfg *CFG) buildUnbuiltBlocks(memoryAccessor *MemoryAccessor, stateAccessor *StateAccessor) int {
	built := 0

	var blocks []*MIRBasicBlock
	for _, bb := range cfg.basicBlocks {
		if bb != nil {
			blocks = append(blocks, bb)
		}
	}

	for _, bb := range blocks {
		if bb.built {
			continue
		}
		incoming := bb.IncomingStacks()
		if len(incoming) == 0 {
			continue
		}

		// Derive stack height from incoming stacks
		var h int
		for _, stack := range incoming {
			h = len(stack)
			break
		}

		// Create entry stack with PHIs if not already set
		if bb.EntryStack() == nil {
			entryStack := ValueStack{}
			for i := 0; i < h; i++ {
				phi := &MIR{
					op:            MirPHI,
					phiStackIndex: h - 1 - i,
				}
				currentEVMBuildPC = bb.FirstPC()
				currentEVMBuildOp = 0
				bb.appendMIR(phi)

				val := Value{
					kind:   Variable,
					def:    phi,
					liveIn: true,
				}
				entryStack.push(&val)
			}
			bb.SetEntryStack(entryStack.clone())
		}

		// Emit JUMPDEST if needed
		if int(bb.FirstPC()) < len(cfg.rawCode) && ByteCode(cfg.rawCode[bb.FirstPC()]) == JUMPDEST {
			currentEVMBuildPC = bb.FirstPC()
			currentEVMBuildOp = byte(JUMPDEST)
			mir := bb.CreateVoidMIR(MirJUMPDEST)
			if mir != nil {
				mir.genStackDepth = h
			}
		}

		// Build the block
		valStack := ValueStack{data: bb.EntryStack()}
		err := cfg.buildBasicBlock(bb, &valStack, memoryAccessor, stateAccessor, nil)
		if err != nil {
			continue
		}
		bb.built = true
		built++
	}

	return built
}

// linkAllPhis links PHI operands for all built canonical blocks.
// Uses SortedParents for deterministic ordering.
func (cfg *CFG) linkAllPhis() {
	var bbs []*MIRBasicBlock
	for _, bb := range cfg.getAllCanonicalBlocks() {
		if bb.built {
			bbs = append(bbs, bb)
		}
	}
	sort.Slice(bbs, func(i, j int) bool {
		return bbs[i].FirstPC() < bbs[j].FirstPC()
	})
	for _, bb := range bbs {
		cfg.linkPhiOperandsForBlock(bb)
	}
}

// simplifyAllPhis simplifies trivial PHIs for all built canonical blocks.
func (cfg *CFG) simplifyAllPhis() {
	var bbs []*MIRBasicBlock
	for _, bb := range cfg.getAllCanonicalBlocks() {
		if bb.built {
			bbs = append(bbs, bb)
		}
	}
	for _, bb := range bbs {
		cfg.simplifyPhiForBlock(bb)
	}
}

// resolveAllPhiTargets resolves PHI-based JUMP/JUMPI targets for all built blocks.
// Returns the number of new targets discovered and connected.
func (cfg *CFG) resolveAllPhiTargets() int {
	newTargetsCount := 0

	var bbs []*MIRBasicBlock
	for _, bb := range cfg.getAllCanonicalBlocks() {
		if bb.built {
			bbs = append(bbs, bb)
		}
	}
	sort.Slice(bbs, func(i, j int) bool {
		return bbs[i].FirstPC() < bbs[j].FirstPC()
	})

	for _, bb := range bbs {
		newTargets := cfg.resolvePhiJumpTargets(bb)
		if len(newTargets) == 0 {
			continue
		}

		children := make([]*MIRBasicBlock, 0, len(newTargets))
		for _, tpc := range newTargets {
			if tpc >= uint64(len(cfg.rawCode)) {
				continue
			}
			if ByteCode(cfg.rawCode[tpc]) != JUMPDEST {
				continue
			}
			targetBB := cfg.getBlockAtPC(uint(tpc))
			if targetBB == nil {
				continue
			}
			children = append(children, targetBB)
		}

		if len(children) > 0 {
			bb.SetChildren(children)
			for _, child := range children {
				existingParents := child.Parents()
				hasParent := false
				for _, p := range existingParents {
					if p == bb {
						hasParent = true
						break
					}
				}
				if !hasParent {
					child.SetParents(append(existingParents, bb))
					newTargetsCount++
				}
				if bb.ExitStack() != nil {
					child.AddIncomingStack(bb, bb.ExitStack())
				}
			}
		}
	}

	return newTargetsCount
}

// ==================== Main CFG Generation ====================

// GenerateMIRCFG generates a MIR Control Flow Graph for the given bytecode
func GenerateMIRCFG(hash common.Hash, code []byte) (*CFG, error) {
	if len(code) == 0 {
		return nil, fmt.Errorf("empty code")
	}

	cfg := NewCFG(hash, code)

	// memoryAccessor is instance local at runtime
	var memoryAccessor *MemoryAccessor = cfg.getMemoryAccessor()
	// stateAccessor is global but we analyze it in processor granularity
	var stateAccessor *StateAccessor = cfg.getStateAccessor()

	// Phase 1, Pass 1: Discovery
	cfg.preScanBlocks()

	// Phase 1, Pass 2: Stack Height Analysis
	heights, err := cfg.analyzeStackHeights()
	if err != nil {
		return nil, fmt.Errorf("stack analysis failed: %w", err)
	}

	// Phase 2: Initial MIR Generation (worklist-based)
	// Build statically reachable blocks first
	canonicalBlocks := cfg.getAllCanonicalBlocks()
	queue := make([]*MIRBasicBlock, 0, len(canonicalBlocks))
	inQueue := make(map[*MIRBasicBlock]bool)

	var initialBlocks []*MIRBasicBlock
	for _, bb := range canonicalBlocks {
		if _, ok := heights[bb]; ok {
			initialBlocks = append(initialBlocks, bb)
		}
	}
	sort.Slice(initialBlocks, func(i, j int) bool {
		return initialBlocks[i].FirstPC() < initialBlocks[j].FirstPC()
	})

	for _, bb := range initialBlocks {
		queue = append(queue, bb)
		inQueue[bb] = true
	}

	i := 0
	for i < len(queue) {
		bb := queue[i]
		i++

		if bb.built {
			continue
		}

		if bb.EntryStack() == nil {
			_, hasStaticHeight := heights[bb]
			if !hasStaticHeight {
				incoming := bb.IncomingStacks()
				if len(incoming) > 0 {
					var parents []*MIRBasicBlock
					for p := range incoming {
						parents = append(parents, p)
					}
					sort.Slice(parents, func(i, j int) bool {
						return parents[i].FirstPC() < parents[j].FirstPC()
					})
					parentStack := incoming[parents[0]]
					heights[bb] = len(parentStack)
				} else {
					continue
				}
			}
		}

		h := heights[bb]

		if int(bb.FirstPC()) < len(cfg.rawCode) && ByteCode(cfg.rawCode[bb.FirstPC()]) == JUMPDEST {
			currentEVMBuildPC = bb.FirstPC()
			currentEVMBuildOp = byte(JUMPDEST)
			mir := bb.CreateVoidMIR(MirJUMPDEST)
			if mir != nil {
				mir.genStackDepth = h
			}
		}

		if bb.EntryStack() == nil {
			entryStack := ValueStack{}
			for i := 0; i < h; i++ {
				phi := &MIR{
					op:            MirPHI,
					phiStackIndex: h - 1 - i,
				}
				currentEVMBuildPC = bb.FirstPC()
				currentEVMBuildOp = 0
				bb.appendMIR(phi)

				val := Value{
					kind:   Variable,
					def:    phi,
					liveIn: true,
				}
				entryStack.push(&val)
			}
			bb.SetEntryStack(entryStack.clone())
		}

		valStack := ValueStack{data: bb.EntryStack()}
		err := cfg.buildBasicBlock(bb, &valStack, memoryAccessor, stateAccessor, nil)
		if err != nil {
			return nil, fmt.Errorf("build basic block %d failed: %w", bb.blockNum, err)
		}
		bb.built = true

		for _, child := range bb.Children() {
			if !child.built && !inQueue[child] {
				queue = append(queue, child)
				inQueue[child] = true
			}
		}
	}

	// Phase 3: Iterative Convergence
	// Loop: Link PHI → Simplify PHI → Resolve targets → Build new blocks
	// Until no new blocks are built and no new targets discovered
	for iteration := 0; iteration < 100; iteration++ {
		// Step 1: Link PHI operands for all built blocks
		cfg.linkAllPhis()

		// Step 2: Simplify trivial PHIs
		cfg.simplifyAllPhis()

		// Step 3: Resolve PHI-based JUMP targets (may discover new targets)
		newTargets := cfg.resolveAllPhiTargets()

		// Step 4: Build newly discovered blocks
		built := cfg.buildUnbuiltBlocks(memoryAccessor, stateAccessor)

		// Convergence check: no new work done
		if built == 0 && newTargets == 0 {
			break
		}
	}

	// Entry block fix
	cfg.buildPCIndex()
	if len(cfg.rawCode) > 2 && ByteCode(cfg.rawCode[2]) == JUMPDEST {
		var entryBB *MIRBasicBlock
		for _, bb := range cfg.basicBlocks {
			if bb != nil && bb.FirstPC() == 0 {
				entryBB = bb
				break
			}
		}
		if entryBB == nil {
			entryBB = cfg.getBlockAtPC(0)
		}
		loopBB := cfg.getBlockAtPC(2)
		if entryBB != nil && entryBB.FirstPC() == 0 && loopBB != nil {
			if entryBB.Size() == 0 {
				entryBB.ResetForRebuild(true)
				valueStack := ValueStack{}
				unprcessedBBs := MIRBasicBlockStack{}
				entryBB.built = false
				entryBB.queued = false
				err := cfg.buildBasicBlock(entryBB, &valueStack, memoryAccessor, stateAccessor, &unprcessedBBs)
				if err != nil {
					return nil, fmt.Errorf("failed to rebuild entry block: %w", err)
				}
				entryBB.built = true
			}
			children := entryBB.Children()
			needsFix := false
			if len(children) == 0 {
				needsFix = true
			} else {
				for _, child := range children {
					if child == nil || child.FirstPC() != 2 {
						needsFix = true
						break
					}
				}
			}
			if needsFix {
				entryBB.children = nil
				entryBB.childrenBitmap = &bitmap{0}
				entryBB.SetChildren([]*MIRBasicBlock{loopBB})
				entryBB.SetLastPC(1)
				existingParents := loopBB.Parents()
				hasEntryAsParent := false
				for _, p := range existingParents {
					if p == entryBB {
						hasEntryAsParent = true
						break
					}
				}
				if !hasEntryAsParent {
					loopBB.SetParents(append(existingParents, entryBB))
				}
				if entryBB.ExitStack() == nil {
					exitStack := ValueStack{}
					exitStack.push(&Value{kind: Variable})
					entryBB.SetExitStack(exitStack.clone())
				}
				loopBB.AddIncomingStack(entryBB, entryBB.ExitStack())
				// Re-link PHI operands for loopBB after adding new parent
				cfg.linkPhiOperandsForBlock(loopBB)
				entryBB.built = true
				entryBB.queued = false
			}
		}
	}

	return cfg, nil
}

// GetBasicBlocks returns the basic blocks in this CFG
func (c *CFG) GetBasicBlocks() []*MIRBasicBlock {
	return c.basicBlocks
}

// buildPCIndex builds a map from PC to basic block for quick lookups.
// Scheme A: this is now a no-op since we use pcToVariants[CanonicalDepth] directly.
// Kept for backward compatibility with existing code paths.
func (c *CFG) buildPCIndex() {
	// Scheme A: pcToVariants[CanonicalDepth] is already populated by createBB.
	// This function is now a no-op but kept for API compatibility.
}

// EnsureSelectorIndexBuilt scans raw bytecode for PUSH4 <selector> and a nearby
// PUSH2 <offset>, then maps selector to the basic block at that offset.
func (c *CFG) EnsureSelectorIndexBuilt() {
	if c.selectorIndex != nil {
		return
	}
	c.buildPCIndex()
	idx := make(map[uint32]*MIRBasicBlock)
	code := c.rawCode
	for i := 0; i+7 < len(code); i++ {
		if code[i] == 0x63 { // PUSH4
			sel := uint32(code[i+1])<<24 | uint32(code[i+2])<<16 | uint32(code[i+3])<<8 | uint32(code[i+4])
			for j := i + 5; j < i+12 && j+2 < len(code); j++ {
				if code[j] == 0x61 { // PUSH2
					off := (uint(code[j+1]) << 8) | uint(code[j+2])
					// Scheme A: use getBlockAtPC instead of pcToBlock
					if bb := c.getBlockAtPC(uint(off)); bb != nil {
						if _, exists := idx[sel]; !exists {
							idx[sel] = bb
						}
					}
					break
				}
			}
		}
	}
	c.selectorIndex = idx
}

// EntryIndexForSelector returns the index within basicBlocks for a selector if known, else -1.
func (c *CFG) EntryIndexForSelector(selector uint32) int {
	c.EnsureSelectorIndexBuilt()
	if c.selectorIndex == nil {
		return -1
	}
	if bb, ok := c.selectorIndex[selector]; ok {
		for i, b := range c.basicBlocks {
			if b == bb {
				return i
			}
		}
	}
	return -1
}

// Compilation-time bytecode generation functions removed
// MIR CFGs are now cached and executed directly by MIRInterpreterAdapter at runtime
func (c *CFG) buildBasicBlock(curBB *MIRBasicBlock, valueStack *ValueStack, memoryAccessor *MemoryAccessor, stateAccessor *StateAccessor, unprcessedBBs *MIRBasicBlockStack) error {
	// Get the raw code from the CFG
	code := c.rawCode
	if code == nil || len(code) == 0 {
		return fmt.Errorf("empty code for basic block")
	}

	// Start processing from the basic block's firstPC position
	i := int(curBB.firstPC)
	if i >= len(code) {
		return fmt.Errorf("invalid starting position %d for basic block", i)
	}

	// Process each byte in the code starting from firstPC
	// Maintain a local depth counter to validate DUP/SWAP semantics without
	// relying on MIR-level stack mutations (which can be optimized to NOPs).
	depth := curBB.InitDepth()
	depthKnown := false

	if curBB.firstPC == 0 {
		firstBytesLen := 10
		if len(code) < firstBytesLen {
			firstBytesLen = len(code)
		}
	}

	// If this block begins at a JUMPDEST, emit the MirJUMPDEST first, then place PHIs after it.
	// This preserves the invariant that PHIs do not precede JUMPDEST and avoids PHI-only blocks.
	if i < len(code) {
		entryOp := ByteCode(code[i])
		if entryOp == JUMPDEST {
			// Record EVM mapping for JUMPDEST and emit it as the first instruction in the block
			currentEVMBuildPC = uint(i)
			currentEVMBuildOp = byte(entryOp)

			// Only emit JUMPDEST if not already present (e.g. inserted by GenerateMIRCFG)
			alreadyPresent := false
			if insts := curBB.Instructions(); len(insts) > 0 && insts[0].op == MirJUMPDEST {
				alreadyPresent = true
			}

			if !alreadyPresent {
				mir := curBB.CreateVoidMIR(MirJUMPDEST)
				if mir != nil {
					mir.genStackDepth = valueStack.size()
				}
			}

			// Advance past JUMPDEST so PHIs (if any) are appended after it and we don't re-emit it below
			i++
		}
	}

	// If this block has multiple parents and recorded incoming stacks, insert PHI nodes to form a unified
	// entry stack and seed the current stack accordingly.
	if len(curBB.Parents()) > 1 && len(curBB.IncomingStacks()) > 0 {
		// Determine the maximum stack height among incoming paths
		maxH := 0
		for _, st := range curBB.IncomingStacks() {
			if l := len(st); l > maxH {
				maxH = l
			}
		}
		// Build PHIs from bottom to top so the last pushed corresponds to top-of-stack
		tmp := ValueStack{}
		for i := maxH - 1; i >= 0; i-- {
			// Collect ith from top across parents if available
			var ops []*Value
			for _, p := range curBB.Parents() {
				st := curBB.IncomingStacks()[p]
				if st != nil && len(st) > i {
					// stack top is end; index from top
					v := st[len(st)-1-i]
					vv := v          // copy
					vv.liveIn = true // mark incoming as live-in so interpreter prefers globalResults
					ops = append(ops, &vv)
				} else {
					// missing value -> append nil to maintain parent alignment
					ops = append(ops, nil)
				}
			}
			// Simplify: if all operands are equal, avoid PHI and push the value directly
			simplified := false
			// First, deduplicate equal operands within this PHI slot
			if len(ops) > 1 {
				uniq := make([]*Value, 0, len(ops))
				for _, o := range ops {
					dup := false
					for _, u := range uniq {
						if equalValueForFlow(o, u) {
							dup = true
							break
						}
					}
					if !dup {
						uniq = append(uniq, o)
					}
				}
				ops = uniq
			}
			if len(ops) > 0 {
				base := ops[0]
				if base != nil && base.kind != Unknown {
					equalAll := true
					for k := 1; k < len(ops); k++ {
						if ops[k] == nil || ops[k].kind == Unknown || !equalValueForFlow(base, ops[k]) {
							equalAll = false
							break
						}
					}
					if equalAll {
						// Push the representative value and continue
						tmp.push(base)
						simplified = true
						// Optional debug

					}
				}
			}
			if simplified {
				continue
			}
			// If a PHI for this slot already exists, merge new operands and reuse it
			var existing *MIR
			for _, m := range curBB.Instructions() {
				if m != nil && m.op == MirPHI && (m.phiStackIndex == i) {
					existing = m
					break
				}
			}
			if existing != nil {
				// Merge incoming operands and deduplicate
				merged := append(append([]*Value{}, existing.operands...), ops...)
				uniq := make([]*Value, 0, len(merged))
				for _, o := range merged {
					dup := false
					for _, u := range uniq {
						if equalValueForFlow(o, u) {
							dup = true
							break
						}
					}
					if !dup {
						uniq = append(uniq, o)
					}
				}
				existing.operands = uniq
				// If only one unique operand remains, bypass PHI
				if len(uniq) == 1 {
					tmp.push(uniq[0])

				} else {
					tmp.push(existing.Result())

				}
			} else {
				// If only one operand after dedup, avoid creating PHI
				if len(ops) == 1 {
					tmp.push(ops[0])

					continue
				}
				phi := curBB.CreatePhiMIR(ops, &tmp)
				if phi != nil {
					phi.phiStackIndex = i

				}
			}
		}
		// tmp now has values bottom-to-top; assign as entry
		curBB.SetEntryStack(tmp.clone())
		valueStack.resetTo(curBB.EntryStack())
		depth = len(curBB.EntryStack())
		depthKnown = true
	} else if es := curBB.EntryStack(); es != nil {
		valueStack.resetTo(es)
		depth = len(es)
		depthKnown = true
	} else if len(curBB.Parents()) == 1 {
		// Single-parent path with inherited stack seeded by the caller.
		// Align local depth tracker with the actual entry stack to avoid
		// spurious DUP/SWAP underflow warnings and ensure exact EVM parity.
		depth = valueStack.size()
		depthKnown = true
	}
	for i < len(code) {
		op := ByteCode(code[i])

		// Count original EVM opcodes for static gas accounting
		if curBB.evmOpCounts != nil {
			curBB.evmOpCounts[byte(op)]++
		}
		// Record EVM location for MIR mapping
		currentEVMBuildPC = uint(i)
		currentEVMBuildOp = byte(op)

		// Handle PUSH operations
		if op >= PUSH1 && op <= PUSH32 {
			size := int(op - PUSH1 + 1)
			if i+size >= len(code) {
				return fmt.Errorf("invalid PUSH operation at position %d", i)
			}
			_ = curBB.CreatePushMIR(size, code[i+1:i+1+size], valueStack)
			depth++
			depthKnown = true
			i += size + 1 // +1 for the opcode itself
			continue
		}

		// Handle other operations
		var mir *MIR
		switch op {
		case STOP:
			mir = curBB.CreateVoidMIR(MirSTOP)
			curBB.SetLastPC(uint(i))
			return nil
		case ADD:
			mir = curBB.CreateBinOpMIR(MirADD, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case MUL:
			mir = curBB.CreateBinOpMIR(MirMUL, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SUB:
			mir = curBB.CreateBinOpMIR(MirSUB, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case DIV:
			mir = curBB.CreateBinOpMIR(MirDIV, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SDIV:
			mir = curBB.CreateBinOpMIR(MirSDIV, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case MOD:
			mir = curBB.CreateBinOpMIR(MirMOD, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SMOD:
			mir = curBB.CreateBinOpMIR(MirSMOD, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case ADDMOD:
			mir = curBB.CreateTernaryOpMIR(MirADDMOD, valueStack)
			if depth >= 3 {
				depth -= 2
			} else {
				depth = 0
			}
		case MULMOD:
			mir = curBB.CreateTernaryOpMIR(MirMULMOD, valueStack)
			if depth >= 3 {
				depth -= 2
			} else {
				depth = 0
			}
		case EXP:
			mir = curBB.CreateBinOpMIR(MirEXP, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SIGNEXTEND:
			mir = curBB.CreateBinOpMIR(MirSIGNEXT, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case LT:
			mir = curBB.CreateBinOpMIR(MirLT, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case GT:
			mir = curBB.CreateBinOpMIR(MirGT, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SLT:
			mir = curBB.CreateBinOpMIR(MirSLT, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SGT:
			mir = curBB.CreateBinOpMIR(MirSGT, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case EQ:
			mir = curBB.CreateBinOpMIR(MirEQ, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case ISZERO:
			mir = curBB.CreateUnaryOpMIR(MirISZERO, valueStack)
		case AND:
			mir = curBB.CreateBinOpMIR(MirAND, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case OR:
			mir = curBB.CreateBinOpMIR(MirOR, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case XOR:
			mir = curBB.CreateBinOpMIR(MirXOR, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case NOT:
			mir = curBB.CreateUnaryOpMIR(MirNOT, valueStack)
		case BYTE:
			mir = curBB.CreateBinOpMIR(MirBYTE, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SHL:
			mir = curBB.CreateBinOpMIR(MirSHL, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SHR:
			mir = curBB.CreateBinOpMIR(MirSHR, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case SAR:
			mir = curBB.CreateBinOpMIR(MirSAR, valueStack)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case KECCAK256:
			mir = curBB.CreateBinOpMIRWithMA(MirKECCAK256, valueStack, memoryAccessor)
			if depth >= 2 {
				depth--
			} else {
				depth = 0
			}
		case ADDRESS:
			mir = curBB.CreateBlockInfoMIR(MirADDRESS, valueStack)
			depth++
			depthKnown = true
		case BALANCE:
			mir = curBB.CreateBlockInfoMIR(MirBALANCE, valueStack)
		case ORIGIN:
			mir = curBB.CreateBlockInfoMIR(MirORIGIN, valueStack)
			depth++
			depthKnown = true
		case CALLER:
			mir = curBB.CreateBlockInfoMIR(MirCALLER, valueStack)
			depth++
			depthKnown = true
		case CALLVALUE:
			mir = curBB.CreateBlockInfoMIR(MirCALLVALUE, valueStack)
			depth++
			depthKnown = true
		case CALLDATALOAD:
			mir = curBB.CreateBlockInfoMIR(MirCALLDATALOAD, valueStack)
		case CALLDATASIZE:
			mir = curBB.CreateBlockInfoMIR(MirCALLDATASIZE, valueStack)
			depth++
			depthKnown = true
		case CALLDATACOPY:
			mir = curBB.CreateBlockInfoMIR(MirCALLDATACOPY, valueStack)
			if depth >= 3 {
				depth -= 3
			} else {
				depth = 0
			}
		case CODESIZE:
			mir = curBB.CreateBlockInfoMIR(MirCODESIZE, valueStack)
			depth++
			depthKnown = true
		case CODECOPY:
			mir = curBB.CreateBlockInfoMIR(MirCODECOPY, valueStack)
			if depth >= 3 {
				depth -= 3
			} else {
				depth = 0
			}
		case GASPRICE:
			mir = curBB.CreateBlockInfoMIR(MirGASPRICE, valueStack)
			depth++
			depthKnown = true
		case EXTCODESIZE:
			mir = curBB.CreateBlockInfoMIR(MirEXTCODESIZE, valueStack)
		case EXTCODECOPY:
			mir = curBB.CreateBlockInfoMIR(MirEXTCODECOPY, valueStack)
			if depth >= 4 {
				depth -= 4
			} else {
				depth = 0
			}
		case RETURNDATASIZE:
			mir = curBB.CreateBlockInfoMIR(MirRETURNDATASIZE, valueStack)
			depth++
			depthKnown = true
		case RETURNDATACOPY:
			mir = curBB.CreateBlockInfoMIR(MirRETURNDATACOPY, valueStack)
			if depth >= 3 {
				depth -= 3
			} else {
				depth = 0
			}
		case EXTCODEHASH:
			mir = curBB.CreateBlockInfoMIR(MirEXTCODEHASH, valueStack)
		case BLOCKHASH:
			mir = curBB.CreateBlockOpMIR(MirBLOCKHASH, valueStack)
		case COINBASE:
			mir = curBB.CreateBlockOpMIR(MirCOINBASE, valueStack)
			depth++
			depthKnown = true
		case TIMESTAMP:
			mir = curBB.CreateBlockOpMIR(MirTIMESTAMP, valueStack)
			depth++
			depthKnown = true
		case NUMBER:
			mir = curBB.CreateBlockOpMIR(MirNUMBER, valueStack)
			depth++
			depthKnown = true
		case DIFFICULTY:
			mir = curBB.CreateBlockOpMIR(MirDIFFICULTY, valueStack)
			depth++
			depthKnown = true
		case GASLIMIT:
			mir = curBB.CreateBlockOpMIR(MirGASLIMIT, valueStack)
			depth++
		case CHAINID:
			mir = curBB.CreateBlockOpMIR(MirCHAINID, valueStack)
			depth++
		case SELFBALANCE:
			mir = curBB.CreateBlockOpMIR(MirSELFBALANCE, valueStack)
			depth++
		case BASEFEE:
			mir = curBB.CreateBlockOpMIR(MirBASEFEE, valueStack)
			depth++
		case POP:
			_ = valueStack.pop()
			// Emit NOP to account for POP base gas (CreateVoidMIR already appends)
			mir = curBB.CreateVoidMIR(MirNOP)
			if depth > 0 {
				depth--
			} else {
				depth = 0
			}
		case MLOAD:
			mir = curBB.CreateMemoryOpMIR(MirMLOAD, valueStack, memoryAccessor)
		case MSTORE:
			mir = curBB.CreateMemoryOpMIR(MirMSTORE, valueStack, memoryAccessor)
			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
		case MSTORE8:
			mir = curBB.CreateMemoryOpMIR(MirMSTORE8, valueStack, memoryAccessor)
			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
		case SLOAD:
			mir = curBB.CreateStorageOpMIR(MirSLOAD, valueStack, stateAccessor)
		case SSTORE:
			mir = curBB.CreateStorageOpMIR(MirSSTORE, valueStack, stateAccessor)
			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
		case JUMP:
			curBB.SetLastPC(uint(i))
			mir = curBB.CreateJumpMIR(MirJUMP, valueStack, nil)

			if depth >= 1 {
				depth--
			} else {
				depth = 0
			}
			if mir != nil {
				// Create a new basic block for the jump target
				// Handle destination: PHI in this block or direct constant
				if len(mir.operands) > 0 && mir.operands[0] != nil {
					d := mir.operands[0]
					if d.kind == Variable && d.def != nil && d.def.op == MirPHI {
						// Collect constant targets by walking the PHI operands (recursively through PHIs and Variables)
						targetSet := make(map[uint64]bool)
						unknown := false
						visited := make(map[*MIR]bool)

						// collectTargets recursively collects all possible constant values from a Value
						var collectTargets func(*Value, int)
						collectTargets = func(v *Value, depth int) {
							if v == nil || depth > 32 {
								unknown = true
								return
							}
							// Direct constant
							if v.kind == Konst {
								if v.payload != nil {
									var tpc uint64
									for _, b := range v.payload {
										tpc = (tpc << 8) | uint64(b)
									}
									targetSet[tpc] = true
								} else if v.u != nil {
									u, _ := v.u.Uint64WithOverflow()
									targetSet[u] = true
								}
								return
							}
							// Variable with def
							if v.kind == Variable && v.def != nil {
								if visited[v.def] {
									return
								}
								visited[v.def] = true

								if v.def.op == MirPHI {
									// PHI node: collect from all operands
									for _, op := range v.def.operands {
										collectTargets(op, depth+1)
									}
								} else {
									// Other operation: try to resolve as constant
									if tpc, ok := tryResolveUint64ConstPC(v, 16); ok {
										targetSet[tpc] = true
									} else {
										unknown = true
									}
								}
								return
							}
							// Unknown kind
							unknown = true
						}

						// Start collection from the PHI
						for _, op := range d.def.operands {
							collectTargets(op, 0)
						}
						visited[d.def] = true
						if unknown && len(targetSet) == 0 {

							// Conservative end: no children, record exit
							curBB.SetExitStack(valueStack.clone())
							return nil
						}
						// Build children for each constant target
						children := make([]*MIRBasicBlock, 0, len(targetSet))
						for tpc := range targetSet {
							if tpc >= uint64(len(code)) {

								continue
							}
							if ByteCode(code[tpc]) != JUMPDEST {
								// Emit an ErrJumpdest marker but continue collecting other valid targets
								errM := curBB.CreateVoidMIR(MirERRJUMPDEST)
								if errM != nil {
									errM.meta = []byte{code[tpc]}
								}
								continue
							}

							targetBB := c.getVariantBlock(uint(tpc), depth, curBB)
							children = append(children, targetBB)

							if !targetBB.built && !targetBB.queued {
								targetBB.queued = true

								if unprcessedBBs != nil {
									unprcessedBBs.Push(targetBB)
								}
							}
						}
						if len(children) == 0 {
							curBB.SetExitStack(valueStack.clone())
							return nil
						}
						curBB.SetChildren(children)
						oldExit := curBB.ExitStack()
						curBB.SetExitStack(valueStack.clone())
						for _, ch := range children {
							ch.SetParents([]*MIRBasicBlock{curBB})
							prev := ch.IncomingStacks()[curBB]
							if prev == nil || !stacksEqual(prev, curBB.ExitStack()) {
								ch.AddIncomingStack(curBB, curBB.ExitStack())
							}
						}
						_ = oldExit
						return nil
					}
					// Fallback: direct constant destination in operand payload
					if d.payload != nil {
						// Interpret payload as big-endian integer
						var targetPC uint64
						for _, b := range d.payload {
							targetPC = (targetPC << 8) | uint64(b)
						}
						if targetPC < uint64(len(code)) {
							isJumpdest := ByteCode(code[targetPC]) == JUMPDEST

							var targetBB *MIRBasicBlock
							if isJumpdest {
								targetBB = c.getVariantBlock(uint(targetPC), depth, curBB)
							} else {
								// model invalid target
								errM := curBB.CreateVoidMIR(MirERRJUMPDEST)
								if errM != nil {
									errM.meta = []byte{code[targetPC]}
								}
								curBB.SetExitStack(valueStack.clone())
								return nil
							}
							curBB.SetChildren([]*MIRBasicBlock{targetBB})
							curBB.SetExitStack(valueStack.clone())
							targetBB.AddIncomingStack(curBB, curBB.ExitStack())

							if !targetBB.built && !targetBB.queued {
								targetBB.queued = true

								if unprcessedBBs != nil {
									unprcessedBBs.Push(targetBB)
								}
							}

							// Ensure the linear fallthrough block (i+1) is created and queued for processing
							// (omitting parent linkage)
							// Scheme A: use hasBlockAtPC instead of pcToBlock
							if !c.hasBlockAtPC(uint(i + 1)) {
								// We use createBB here because it's not a CFG edge, just ensuring existence
								fall := c.createBB(uint(i+1), nil)
								if !fall.queued {
									fall.queued = true
									if unprcessedBBs != nil {
										unprcessedBBs.Push(fall)
									}
								}
							}
							return nil
						}
						// Unknown/indirect destination value

						curBB.SetExitStack(valueStack.clone())
						return nil
					}
				}
			}
			return nil
		case JUMPI:
			curBB.SetLastPC(uint(i))
			mir = curBB.CreateJumpMIR(MirJUMPI, valueStack, nil)

			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
			if mir != nil {
				// Create new basic blocks for both true (target) and false (fallthrough) paths
				// Handle destination: PHI recursively or direct constant, else unknown
				if len(mir.operands) > 0 && mir.operands[0] != nil {
					d := mir.operands[0]
					if d.kind == Variable && d.def != nil && d.def.op == MirPHI {
						targetSet := make(map[uint64]bool)
						unknown := false
						for _, ov := range d.def.operands {
							if ov == nil {
								unknown = true
								break
							}
							if ov.kind == Konst && ov.payload != nil {
								var tpc uint64
								for _, b := range ov.payload {
									tpc = (tpc << 8) | uint64(b)
								}

								targetSet[tpc] = true
							} else {
								// Attempt a small constant evaluation; if fails, mark unknown
								if tpc, ok := tryResolveUint64ConstPC(ov, 16); ok {

									targetSet[tpc] = true
								} else {
									unknown = true
									break
								}
							}
						}
						if unknown || len(targetSet) == 0 {

							// Create only fallthrough conservatively; reuse existing if present
							fallthroughBB := c.getVariantBlock(uint(i+1), depth, curBB)
							curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
							curBB.SetExitStack(valueStack.clone())
							fallthroughBB.SetParents([]*MIRBasicBlock{curBB})
							prev := fallthroughBB.IncomingStacks()[curBB]
							if prev == nil || !stacksEqual(prev, curBB.ExitStack()) {
								fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
							}
							if !fallthroughBB.queued {
								fallthroughBB.queued = true
								if unprcessedBBs != nil {
									unprcessedBBs.Push(fallthroughBB)
								}
							}
							return nil
						}
						// Build target and fallthrough edges
						fallthroughBB := c.getVariantBlock(uint(i+1), depth, curBB)
						children := []*MIRBasicBlock{fallthroughBB}

						for tpc := range targetSet {
							if tpc >= uint64(len(code)) {

								continue
							}
							if ByteCode(code[tpc]) != JUMPDEST {
								// For JUMPI: skip invalid targets, don't create MirERRJUMPDEST.
								// Runtime will handle if this target is selected and invalid.
								continue
							}

							targetBB := c.getVariantBlock(uint(tpc), depth, curBB)
							children = append(children, targetBB)

							if !targetBB.built && !targetBB.queued {
								targetBB.queued = true

								if unprcessedBBs != nil {
									unprcessedBBs.Push(targetBB)
								}
							}
						}
						curBB.SetChildren(children)
						curBB.SetExitStack(valueStack.clone())
						for _, ch := range children {
							// getVariantBlock already sets parent if needed, but ensure stack linkage
							prevIn := ch.IncomingStacks()[curBB]
							if prevIn == nil || !stacksEqual(prevIn, curBB.ExitStack()) {
								ch.AddIncomingStack(curBB, curBB.ExitStack())
							}
						}

						if !fallthroughBB.built && !fallthroughBB.queued {
							fallthroughBB.queued = true
							if unprcessedBBs != nil {
								unprcessedBBs.Push(fallthroughBB)
							}
						}
						return nil
					}
					// Fallback: direct constant target in operand payload
					if d.payload != nil {
						// Interpret payload as big-endian integer of arbitrary length
						var targetPC uint64
						for _, b := range d.payload {
							targetPC = (targetPC << 8) | uint64(b)
						}
						if targetPC < uint64(len(code)) {
							isJumpdest := ByteCode(code[targetPC]) == JUMPDEST

							// Create blocks for target and fallthrough
							var targetBB *MIRBasicBlock
							if isJumpdest {
								targetBB = c.getVariantBlock(uint(targetPC), depth, curBB)
							} else {
								// For JUMPI with invalid target: do NOT create MirERRJUMPDEST.
								// Let runtime handle it - if condition is 0, we fallthrough and no error.
								// If condition is non-zero, scheduleJump will report the error.
								// Still create fallthrough block only (no target block)
								fallthroughBB := c.getVariantBlock(uint(i+1), depth, curBB)
								fallthroughBB.SetInitDepthMax(depth)
								curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
								curBB.SetExitStack(valueStack.clone())
								fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())

								if !fallthroughBB.built && !fallthroughBB.queued {
									fallthroughBB.queued = true
									if unprcessedBBs != nil {
										unprcessedBBs.Push(fallthroughBB)
									}
								}
								return nil
							}
							// JUMPI: create both target and fallthrough blocks
							fallthroughBB := c.getVariantBlock(uint(i+1), depth, curBB)
							targetBB.SetInitDepthMax(depth)
							fallthroughBB.SetInitDepthMax(depth)
							curBB.SetChildren([]*MIRBasicBlock{fallthroughBB, targetBB})
							// Record exit stack and add as incoming to both successors
							curBB.SetExitStack(valueStack.clone())
							targetBB.AddIncomingStack(curBB, curBB.ExitStack())
							fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())

							if !targetBB.built && !targetBB.queued {
								targetBB.queued = true
								if unprcessedBBs != nil {
									unprcessedBBs.Push(targetBB)
								}
							}
							if !fallthroughBB.built && !fallthroughBB.queued {
								fallthroughBB.queued = true
								if unprcessedBBs != nil {
									unprcessedBBs.Push(fallthroughBB)
								}
							}
							return nil
						}
						// Unknown/indirect target: still create fallthrough edge conservatively

						fallthroughBB := c.getVariantBlock(uint(i+1), depth, curBB)
						curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
						curBB.SetExitStack(valueStack.clone())
						prev := fallthroughBB.IncomingStacks()[curBB]
						if prev == nil || !stacksEqual(prev, curBB.ExitStack()) {
							fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
						}
						if !fallthroughBB.built && !fallthroughBB.queued {
							fallthroughBB.queued = true
							if unprcessedBBs != nil {
								unprcessedBBs.Push(fallthroughBB)
							}
						}
						return nil
					}
					// Interpret payload as big-endian integer of arbitrary length
					var targetPC uint64
					for _, b := range mir.operands[0].payload {
						targetPC = (targetPC << 8) | uint64(b)
					}
					if d.IsConst() && targetPC < uint64(len(code)) {
						isJumpdest := ByteCode(code[targetPC]) == JUMPDEST
						// Determine existence and whether either edge is newly added
						// Scheme A: use getBlockAtPC instead of pcToBlock
						var hadTargetParentBefore bool
						var hadFallParentBefore bool
						existingTarget := c.getBlockAtPC(uint(targetPC))
						targetExists := existingTarget != nil
						if targetExists {
							for _, p := range existingTarget.Parents() {
								if p == curBB {
									hadTargetParentBefore = true
									break
								}
							}
						}
						existingFall := c.getBlockAtPC(uint(i + 1))
						fallExists := existingFall != nil
						if fallExists {
							for _, p := range existingFall.Parents() {
								if p == curBB {
									hadFallParentBefore = true
									break
								}
							}
						}
						// Create blocks for target and fallthrough
						var targetBB *MIRBasicBlock
						if isJumpdest {
							targetBB = c.getVariantBlock(uint(targetPC), depth, curBB)
						} else {
							// For JUMPI with invalid target: do NOT create MirERRJUMPDEST.
							// Let runtime handle it - if condition is 0, we fallthrough and no error.
							// Still create fallthrough block only (no target block)
							fallthroughBB := c.createBB(uint(i+1), curBB)
							fallthroughBB.SetInitDepthMax(depth)
							curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
							curBB.SetExitStack(valueStack.clone())
							prev := fallthroughBB.IncomingStacks()[curBB]
							if prev == nil || !stacksEqual(prev, curBB.ExitStack()) {
								fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
							}
							if !fallExists || (fallExists && !hadFallParentBefore) {
								if !fallthroughBB.queued {
									fallthroughBB.queued = true
									if unprcessedBBs != nil {
										unprcessedBBs.Push(fallthroughBB)
									}
								}
							}
							return nil
						}
						fallthroughBB := c.createBB(uint(i+1), curBB)
						targetBB.SetInitDepthMax(depth)
						fallthroughBB.SetInitDepthMax(depth)
						curBB.SetChildren([]*MIRBasicBlock{targetBB, fallthroughBB})
						// Record exit stack and add as incoming to both successors
						curBB.SetExitStack(valueStack.clone())
						targetBB.AddIncomingStack(curBB, curBB.ExitStack())
						prevFall := fallthroughBB.IncomingStacks()[curBB]
						if prevFall == nil || !stacksEqual(prevFall, curBB.ExitStack()) {
							fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
						}
						if !targetExists || (targetExists && !hadTargetParentBefore) {
							if !targetBB.queued {
								targetBB.queued = true
								if unprcessedBBs != nil {
									unprcessedBBs.Push(targetBB)
								}
							}
						}
						if !fallthroughBB.built && !fallthroughBB.queued {
							fallthroughBB.queued = true
							if unprcessedBBs != nil {
								unprcessedBBs.Push(fallthroughBB)
							}
						}
						return nil
					} else {
						// Target outside code range; create only fallthrough and warn

						fallthroughBB := c.getVariantBlock(uint(i+1), depth, curBB)
						curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
						curBB.SetExitStack(valueStack.clone())
						prev := fallthroughBB.IncomingStacks()[curBB]
						if prev == nil || !stacksEqual(prev, curBB.ExitStack()) {
							fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
						}
						if !fallthroughBB.built && !fallthroughBB.queued {
							fallthroughBB.queued = true
							if unprcessedBBs != nil {
								unprcessedBBs.Push(fallthroughBB)
							}
						}
						return nil
					}
				} else {
					// Unknown/indirect target: still create fallthrough edge conservatively

					fallthroughBB := c.getVariantBlock(uint(i+1), depth, curBB)
					fallthroughBB.SetInitDepthMax(depth)
					curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
					curBB.SetExitStack(valueStack.clone())
					prev := fallthroughBB.IncomingStacks()[curBB]
					if prev == nil || !stacksEqual(prev, curBB.ExitStack()) {
						fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
					}
					if !fallthroughBB.built && !fallthroughBB.queued {
						fallthroughBB.queued = true

						if unprcessedBBs != nil {
							unprcessedBBs.Push(fallthroughBB)
						}
					}
					return nil
				}
			}
			return nil
		case RJUMP:
			// Not implemented yet; tolerate by skipping to keep tests functional
			return nil
		case RJUMPI:
			// Not implemented yet; tolerate by skipping to keep tests functional
			return nil
		case RJUMPV:
			// Not implemented yet; tolerate by skipping to keep tests functional
			return nil
		case JUMPDEST:
			// If we hit a JUMPDEST, we should create a new basic block
			// unless this is the first instruction of the block
			// General rule: if we've processed any instructions (i > firstPC), create a new block
			// This handles cases where Size()=0 but we've still processed instructions (e.g., PUSH)
			if uint(i) > curBB.firstPC {
				// Split block: current block ends at i-1, new block (variant) starts at i
				newBB := c.getVariantBlock(uint(i), depth, curBB)

				curBB.SetChildren([]*MIRBasicBlock{newBB})
				curBB.SetLastPC(uint(i - 1))
				curBB.SetExitStack(valueStack.clone())

				// AddIncomingStack handles deduplication of stacks
				newBB.AddIncomingStack(curBB, curBB.ExitStack())

				// Queue if new or not built
				if !newBB.built && !newBB.queued {
					newBB.queued = true

					if unprcessedBBs != nil {
						unprcessedBBs.Push(newBB)
					}
				}
				return nil
			}

			mir = curBB.CreateVoidMIR(MirJUMPDEST)
			// Ensure generation-time stack depth reflects current entry depth
			if mir != nil {
				mir.genStackDepth = valueStack.size()
			}
		case PC:
			mir = curBB.CreateBlockInfoMIR(MirPC, valueStack)
			depth++
		case MSIZE:
			mir = curBB.CreateMemoryOpMIR(MirMSIZE, valueStack, memoryAccessor)
			depth++
		case GAS:
			mir = curBB.CreateBlockInfoMIR(MirGAS, valueStack)
			depth++
		case BLOBHASH:
			mir = curBB.CreateBlockInfoMIR(MirBLOBHASH, valueStack)
		case BLOBBASEFEE:
			mir = curBB.CreateBlockInfoMIR(MirBLOBBASEFEE, valueStack)
			depth++
		case TLOAD:
			mir = curBB.CreateStorageOpMIR(MirTLOAD, valueStack, stateAccessor)
		case TSTORE:
			mir = curBB.CreateStorageOpMIR(MirTSTORE, valueStack, stateAccessor)
			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
		case MCOPY:
			// MCOPY takes 3 operands: dest, src, length
			length := valueStack.pop()
			src := valueStack.pop()
			dest := valueStack.pop()
			mir = new(MIR)
			mir.op = MirMCOPY
			mir.operands = []*Value{&dest, &src, &length}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(src, length)
				memoryAccessor.recordStore(dest, length, Value{kind: Variable})
			}
			// MCOPY does not produce a stack value
			if mir != nil {
				curBB.appendMIR(mir)
			}
			if depth >= 3 {
				depth -= 3
			} else {
				depth = 0
			}
		case PUSH0:
			_ = curBB.CreatePushMIR(0, []byte{}, valueStack)
			depth++
		case LOG0:
			mir = curBB.CreateLogMIR(MirLOG0, valueStack)
			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
		case LOG1:
			mir = curBB.CreateLogMIR(MirLOG1, valueStack)
			if depth >= 3 {
				depth -= 3
			} else {
				depth = 0
			}
		case LOG2:
			mir = curBB.CreateLogMIR(MirLOG2, valueStack)
			if depth >= 4 {
				depth -= 4
			} else {
				depth = 0
			}
		case LOG3:
			mir = curBB.CreateLogMIR(MirLOG3, valueStack)
			if depth >= 5 {
				depth -= 5
			} else {
				depth = 0
			}
		case LOG4:
			mir = curBB.CreateLogMIR(MirLOG4, valueStack)
			if depth >= 6 {
				depth -= 6
			} else {
				depth = 0
			}
		case CREATE:
			curBB.SetLastPC(uint(i)) // Mark end of current block before CREATE
			// CREATE takes 3 operands: value, offset, size
			// EVM stack layout (top to bottom): value, offset, size
			value := valueStack.pop()
			offset := valueStack.pop()
			size := valueStack.pop()
			mir = new(MIR)
			mir.op = MirCREATE
			mir.operands = []*Value{&value, &offset, &size}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(offset, size)
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			targetDepth := 1
			if depth >= 3 {
				targetDepth = depth - 3 + 1
			}

			fallthroughBB := c.getVariantBlock(uint(i+1), targetDepth, curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if !fallthroughBB.built && !fallthroughBB.queued {
				fallthroughBB.queued = true
				if unprcessedBBs != nil {
					unprcessedBBs.Push(fallthroughBB)
				}
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			depth = targetDepth
			return nil
		case CREATE2:
			curBB.SetLastPC(uint(i)) // Mark end of current block before CREATE2
			// CREATE2 takes 4 operands: value, offset, size, salt
			// EVM stack layout (top to bottom): value, offset, size, salt
			value := valueStack.pop()
			offset := valueStack.pop()
			size := valueStack.pop()
			salt := valueStack.pop()
			mir = new(MIR)
			mir.op = MirCREATE2
			mir.operands = []*Value{&value, &offset, &size, &salt}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(offset, size)
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			targetDepth := 1
			if depth >= 4 {
				targetDepth = depth - 4 + 1
			}

			fallthroughBB := c.getVariantBlock(uint(i+1), targetDepth, curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if !fallthroughBB.built && !fallthroughBB.queued {
				fallthroughBB.queued = true
				if unprcessedBBs != nil {
					unprcessedBBs.Push(fallthroughBB)
				}
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			depth = targetDepth
			return nil
		case CALL:
			curBB.SetLastPC(uint(i)) // Mark end of current block before CALL
			// CALL takes 7 operands: gas, addr, value, inOffset, inSize, outOffset, outSize
			// Pop from stack top to bottom (LIFO): gas is on top
			gas := valueStack.pop()
			addr := valueStack.pop()
			value := valueStack.pop()
			inOffset := valueStack.pop()
			inSize := valueStack.pop()
			outOffset := valueStack.pop()
			outSize := valueStack.pop()
			mir = new(MIR)
			mir.op = MirCALL
			mir.operands = []*Value{&gas, &addr, &value, &inOffset, &inSize, &outOffset, &outSize}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(inOffset, inSize)
				memoryAccessor.recordStore(outOffset, outSize, Value{kind: Variable})
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			targetDepth := 1
			if depth >= 7 {
				targetDepth = depth - 7 + 1
			}

			fallthroughBB := c.getVariantBlock(uint(i+1), targetDepth, curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if !fallthroughBB.built && !fallthroughBB.queued {
				fallthroughBB.queued = true
				if unprcessedBBs != nil {
					unprcessedBBs.Push(fallthroughBB)
				}
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			depth = targetDepth
			return nil
		case CALLCODE:
			curBB.SetLastPC(uint(i)) // Mark end of current block before CALLCODE
			// CALLCODE takes same operands as CALL
			// Pop from stack top to bottom (LIFO): gas is on top
			gas := valueStack.pop()
			addr := valueStack.pop()
			value := valueStack.pop()
			inOffset := valueStack.pop()
			inSize := valueStack.pop()
			outOffset := valueStack.pop()
			outSize := valueStack.pop()
			mir = new(MIR)
			mir.op = MirCALLCODE
			mir.operands = []*Value{&gas, &addr, &value, &inOffset, &inSize, &outOffset, &outSize}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(inOffset, inSize)
				memoryAccessor.recordStore(outOffset, outSize, Value{kind: Variable})
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			targetDepth := 1
			if depth >= 7 {
				targetDepth = depth - 7 + 1
			}

			fallthroughBB := c.getVariantBlock(uint(i+1), targetDepth, curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if !fallthroughBB.built && !fallthroughBB.queued {
				fallthroughBB.queued = true
				if unprcessedBBs != nil {
					unprcessedBBs.Push(fallthroughBB)
				}
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			depth = targetDepth
			return nil
		case RETURN:
			// RETURN takes 2 operands: offset (top), size
			offset := valueStack.pop()
			size := valueStack.pop()
			mir = new(MIR)
			mir.op = MirRETURN
			mir.operands = []*Value{&offset, &size}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(offset, size)
			}
			if mir != nil {
				curBB.appendMIR(mir)
			}
			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
			return nil
		case DELEGATECALL:
			curBB.SetLastPC(uint(i)) // Mark end of current block before DELEGATECALL
			// DELEGATECALL takes 6 operands: gas, addr, inOffset, inSize, outOffset, outSize
			// Pop from stack top to bottom (LIFO): gas is on top
			gas := valueStack.pop()
			addr := valueStack.pop()
			inOffset := valueStack.pop()
			inSize := valueStack.pop()
			outOffset := valueStack.pop()
			outSize := valueStack.pop()
			mir = new(MIR)
			mir.op = MirDELEGATECALL
			mir.operands = []*Value{&gas, &addr, &inOffset, &inSize, &outOffset, &outSize}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(inOffset, inSize)
				memoryAccessor.recordStore(outOffset, outSize, Value{kind: Variable})
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			targetDepth := 1
			if depth >= 6 {
				targetDepth = depth - 6 + 1
			}

			fallthroughBB := c.getVariantBlock(uint(i+1), targetDepth, curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if !fallthroughBB.built && !fallthroughBB.queued {
				fallthroughBB.queued = true
				if unprcessedBBs != nil {
					unprcessedBBs.Push(fallthroughBB)
				}
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			depth = targetDepth
			return nil
		case STATICCALL:
			curBB.SetLastPC(uint(i)) // Mark end of current block before STATICCALL
			// STATICCALL takes 6 operands: gas, addr, inOffset, inSize, outOffset, outSize
			// Pop from stack top to bottom (LIFO): gas is on top
			gas := valueStack.pop()
			addr := valueStack.pop()
			inOffset := valueStack.pop()
			inSize := valueStack.pop()
			outOffset := valueStack.pop()
			outSize := valueStack.pop()
			mir = new(MIR)
			mir.op = MirSTATICCALL
			mir.operands = []*Value{&gas, &addr, &inOffset, &inSize, &outOffset, &outSize}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(inOffset, inSize)
				memoryAccessor.recordStore(outOffset, outSize, Value{kind: Variable})
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			targetDepth := 1
			if depth >= 6 {
				targetDepth = depth - 6 + 1
			}

			fallthroughBB := c.getVariantBlock(uint(i+1), targetDepth, curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if !fallthroughBB.built && !fallthroughBB.queued {
				fallthroughBB.queued = true
				if unprcessedBBs != nil {
					unprcessedBBs.Push(fallthroughBB)
				}
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			depth = targetDepth
			return nil
		case REVERT:
			// REVERT takes 2 operands: offset, size (pop offset first, then size)
			offset := valueStack.pop()
			size := valueStack.pop()
			mir = new(MIR)
			mir.op = MirREVERT
			mir.operands = []*Value{&offset, &size}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(offset, size)
			}
			if mir != nil {
				curBB.appendMIR(mir)
			}
			if depth >= 2 {
				depth -= 2
			} else {
				depth = 0
			}
			// REVERT terminates the current basic block with no children
			curBB.SetChildren(nil)
			return nil
		case INVALID:
			mir = curBB.CreateVoidMIR(MirINVALID)
			return nil
		case SELFDESTRUCT:
			// SELFDESTRUCT takes 1 operand: address
			addr := valueStack.pop()
			mir = new(MIR)
			mir.op = MirSELFDESTRUCT
			mir.operands = []*Value{&addr}
			if mir != nil {
				curBB.appendMIR(mir)
			}
			return nil
			// Stack operations - DUP1 to DUP16 (fail CFG build if stack too shallow)
		case DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8, DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16:
			n := int(op - DUP1 + 1)
			if depthKnown && depth < n {
				// Depth underflow: still emit a logical DUP via CreateStackOpMIR so
				// the resulting MIR/stack model remains consistent, but do not log.
			}
			mir = curBB.CreateStackOpMIR(MirOperation(0x80+byte(n-1)), valueStack)
			if depth >= n {
				depth++
			}
			// Stack operations - SWAP1 to SWAP16 (fail CFG build if stack too shallow)
		case SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8, SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16:
			n := int(op - SWAP1 + 1)
			if depthKnown && depth <= n {
				// Depth underflow: still emit logical SWAP via CreateStackOpMIR but skip logging.
			}
			mir = curBB.CreateStackOpMIR(MirOperation(0x90+byte(n-1)), valueStack)
		// EOF operations
		case DATALOAD:
			mir = curBB.CreateBlockInfoMIR(MirDATALOAD, valueStack)
		case DATALOADN:
			mir = curBB.CreateBlockInfoMIR(MirDATALOADN, valueStack)
		case DATASIZE:
			mir = curBB.CreateBlockInfoMIR(MirDATASIZE, valueStack)
		case DATACOPY:
			mir = curBB.CreateBlockInfoMIR(MirDATACOPY, valueStack)
		case CALLF:
			// CALLF takes 2 operands: gas, function_id
			functionID := valueStack.pop()
			gas := valueStack.pop()
			mir = new(MIR)
			mir.op = MirCALLF
			mir.operands = []*Value{&gas, &functionID}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			// Depth: pop2 push1
			if depth >= 2 {
				depth = depth - 2 + 1
			} else {
				depth = 1
			}
			fallthroughBB := c.createBB(uint(i+1), curBB)
			fallthroughBB.SetInitDepth(depth)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if unprcessedBBs != nil {
				unprcessedBBs.Push(fallthroughBB)
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			return nil
		case RETF:
			mir = curBB.CreateVoidMIR(MirRETF)
			return nil
		case JUMPF:
			mir = curBB.CreateJumpMIR(MirJUMPF, valueStack, nil)
			return nil
		case DUPN:
			mir = curBB.CreateStackOpMIR(MirDUPN, valueStack)
		case SWAPN:
			mir = curBB.CreateStackOpMIR(MirSWAPN, valueStack)
		case EXCHANGE:
			mir = curBB.CreateStackOpMIR(MirEXCHANGE, valueStack)
		case EOFCREATE:
			// EOFCREATE takes 4 operands: value, code_offset, code_size, salt
			salt := valueStack.pop()
			codeSize := valueStack.pop()
			codeOffset := valueStack.pop()
			value := valueStack.pop()
			mir = new(MIR)
			mir.op = MirEOFCREATE
			mir.operands = []*Value{&value, &codeOffset, &codeSize, &salt}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			// Depth: pop4 push1
			if depth >= 4 {
				depth = depth - 4 + 1
			} else {
				depth = 1
			}
			fallthroughBB := c.createBB(uint(i+1), curBB)
			fallthroughBB.SetInitDepth(depth)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if unprcessedBBs != nil {
				unprcessedBBs.Push(fallthroughBB)
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			return nil
		case RETURNCONTRACT:
			mir = curBB.CreateVoidMIR(MirRETURNCONTRACT)
		// Additional opcodes
		case RETURNDATALOAD:
			mir = curBB.CreateBlockInfoMIR(MirRETURNDATALOAD, valueStack)
		case EXTCALL:
			// EXTCALL takes 7 operands: gas, addr, value, inOffset, inSize, outOffset, outSize
			outSize := valueStack.pop()
			outOffset := valueStack.pop()
			inSize := valueStack.pop()
			inOffset := valueStack.pop()
			value := valueStack.pop()
			addr := valueStack.pop()
			gas := valueStack.pop()
			mir = new(MIR)
			mir.op = MirEXTCALL
			mir.operands = []*Value{&gas, &addr, &value, &inOffset, &inSize, &outOffset, &outSize}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(inOffset, inSize)
				memoryAccessor.recordStore(outOffset, outSize, Value{kind: Variable})
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB := c.getVariantBlock(uint(i+1), len(curBB.ExitStack()), curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if unprcessedBBs != nil {
				unprcessedBBs.Push(fallthroughBB)
			}
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			return nil
		case EXTDELEGATECALL:
			// EXTDELEGATECALL takes 6 operands: gas, addr, inOffset, inSize, outOffset, outSize
			outSize := valueStack.pop()
			outOffset := valueStack.pop()
			inSize := valueStack.pop()
			inOffset := valueStack.pop()
			addr := valueStack.pop()
			gas := valueStack.pop()
			mir = new(MIR)
			mir.op = MirEXTDELEGATECALL
			mir.operands = []*Value{&gas, &addr, &inOffset, &inSize, &outOffset, &outSize}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(inOffset, inSize)
				memoryAccessor.recordStore(outOffset, outSize, Value{kind: Variable})
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB := c.getVariantBlock(uint(i+1), len(curBB.ExitStack()), curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if unprcessedBBs != nil {
				unprcessedBBs.Push(fallthroughBB)
			}
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			return nil
		case EXTSTATICCALL:
			// EXTSTATICCALL takes 6 operands: gas, addr, inOffset, inSize, outOffset, outSize
			outSize := valueStack.pop()
			outOffset := valueStack.pop()
			inSize := valueStack.pop()
			inOffset := valueStack.pop()
			addr := valueStack.pop()
			gas := valueStack.pop()
			mir = new(MIR)
			mir.op = MirEXTSTATICCALL
			mir.operands = []*Value{&gas, &addr, &inOffset, &inSize, &outOffset, &outSize}
			if memoryAccessor != nil {
				memoryAccessor.recordLoad(inOffset, inSize)
				memoryAccessor.recordStore(outOffset, outSize, Value{kind: Variable})
			}
			valueStack.push(mir.Result())
			if mir != nil {
				curBB.appendMIR(mir)
			}
			curBB.SetExitStack(valueStack.clone())
			fallthroughBB := c.getVariantBlock(uint(i+1), len(curBB.ExitStack()), curBB)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})

			if unprcessedBBs != nil {
				unprcessedBBs.Push(fallthroughBB)
			}
			fallthroughBB.AddIncomingStack(curBB, curBB.ExitStack())
			return nil
		default:
			// Tolerate customized/fused opcodes (0xb0-0xcf) by treating them as NOPs
			if op >= 0xb0 && op <= 0xcf {
				_ = curBB.CreateVoidMIR(MirNOP)
				// continue scanning
				break
			}
			// For any other unknown opcode, terminate the current basic block
			// as if hitting INVALID (unreachable metadata/data regions)
			_ = curBB.CreateVoidMIR(MirINVALID)
			curBB.SetLastPC(uint(i))
			return nil
		}

		// Record source pc on generated MIR (best-effort; some early-return paths set it earlier or remain nil)
		if mir != nil {
			pcCopy := uint(i)
			mir.pc = &pcCopy
		}

		i++
	}
	// Special handling for entry block (firstPC == 0): ensure it falls through to PC:2 if it's JUMPDEST
	// This fixes cases where the entry block should end after PUSH1 and fall through to the loop block
	if curBB.firstPC == 0 && len(code) > 2 && ByteCode(code[2]) == JUMPDEST {
		// Use getVariantBlock to handle stack polymorphism correctly
		fallthroughBB := c.getVariantBlock(2, depth, curBB)

		// Ensure child relationship
		hasCorrectChild := false
		for _, child := range curBB.Children() {
			if child == fallthroughBB {
				hasCorrectChild = true
				break
			}
		}

		if !hasCorrectChild {
			// Always set the correct child (replace any wrong ones)
			curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
			curBB.SetExitStack(valueStack.clone())

			// getVariantBlock handles parent linkage and queueing

			curBB.SetLastPC(1) // Entry block ends at PC:1 (after PUSH1 0x03)

		}
	}
	// If we've finished processing the block, check if the next instruction is a JUMPDEST
	// and ensure we have a fallthrough connection to it
	// This is especially important for the entry block (firstPC == 0) which should
	// fall through to the first JUMPDEST after PUSH instructions
	if i < len(code) {
		nextOp := ByteCode(code[i])
		if nextOp == JUMPDEST {
			// Use getVariantBlock to handle stack polymorphism correctly
			fallthroughBB := c.getVariantBlock(uint(i), depth, curBB)

			// Check if we have the correct child at this PC
			hasCorrectChild := false
			for _, child := range curBB.Children() {
				if child == fallthroughBB {
					hasCorrectChild = true
					break
				}
			}

			// If we don't have the correct child, create/use the fallthrough block
			// Always replace wrong children with the correct one
			if !hasCorrectChild || len(curBB.Children()) == 0 {
				// Always set the correct child (replace any wrong ones)
				curBB.SetChildren([]*MIRBasicBlock{fallthroughBB})
				curBB.SetExitStack(valueStack.clone())

				// getVariantBlock handles parent linkage and queueing

				curBB.SetLastPC(uint(i - 1))

			}
		}
	}
	return nil
}
