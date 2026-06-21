import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaBrain, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const ReverseEngineering = () => {
  const [expandedSection, setExpandedSection] = useState(null);
  const { addToHistory } = useCommandHistory();

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleCopy = (command) => {
    copyToClipboard(command);
    addToHistory(command);
    toast.success('Copied to clipboard!');
  };

  const sections = [
    {
      id: 'intro',
      title: '🔬 What is Reverse Engineering? (Beginner)',
      content: [
        {
          type: 'markdown',
          value: `**Reverse Engineering (RE)** is the process of analyzing a compiled binary to understand how it works — without having the source code. It is used for:

- **Malware analysis** — Understanding what a virus/ransomware does
- **CTF challenges** — Solving "reversing" category challenges
- **Vulnerability research** — Finding bugs in closed-source software
- **Software compatibility** — Understand proprietary file formats/protocols

## The RE Toolkit

| Tool | Platform | Use Case |
|------|----------|---------|
| **Ghidra** | Any | Free NSA decompiler — converts binary back to C-like code |
| **IDA Pro** | Any | Industry standard (expensive), best disassembler |
| **x64dbg / x32dbg** | Windows | Dynamic analysis — step through code as it runs |
| **gdb + pwndbg** | Linux | GNU debugger with enhanced UI |
| **Radare2 / Cutter** | Any | Free, powerful CLI/GUI framework |
| **strings** | Any | Extract readable text from binary |
| **file** | Any | Identify file type from magic bytes |
| **ltrace / strace** | Linux | Trace library/system calls at runtime |
| **objdump** | Linux | Disassemble ELF binaries |`
        },
        {
          type: 'step',
          title: '1. First Steps — Triage a Binary',
          description: 'Always start by learning as much as possible before opening a debugger.',
          commands: [
            { value: 'file binary', description: 'Identify file type (ELF, PE, Mach-O, etc.)' },
            { value: 'strings binary | head -50', description: 'Extract all readable strings (passwords, URLs, function names)' },
            { value: 'strings binary | grep -E "http|pass|key|flag"', description: 'Filter strings for interesting keywords' },
            { value: 'xxd binary | head -20', description: 'View raw bytes (look at magic bytes)' },
            { value: 'objdump -d binary | head -100', description: 'Quick disassembly of first 100 lines' },
            { value: 'ltrace ./binary', description: 'Trace library calls (strcmp, printf, malloc)' },
            { value: 'strace ./binary', description: 'Trace system calls (open, read, write, execve)' },
          ]
        },
        {
          type: 'step',
          title: '2. Static Analysis with Ghidra',
          description: 'Analyze without running the binary — decompile it to C-like pseudocode.',
          commands: [
            { value: 'ghidraRun', description: 'Launch Ghidra (or click icon)' },
            { value: '# File > New Project > Import Binary file', description: 'Import the binary into Ghidra' },
            { value: '# Double-click the binary → Analyze (Yes to all)', description: 'Run all auto-analysis passes' },
            { value: '# Symbol Tree → Functions → main', description: 'Navigate to main() function' },
            { value: '# Windows → Decompiler → View C-like code', description: 'View decompiled pseudocode' },
          ]
        },
        {
          type: 'step',
          title: '3. Dynamic Analysis with x64dbg (Windows)',
          description: 'Run the binary and step through instructions to observe behavior.',
          commands: [
            { value: 'x64dbg.exe', description: 'Open x64dbg' },
            { value: '# File > Open > Load binary', description: 'Load binary into debugger' },
            { value: '# F2 on interesting address → toggle breakpoint', description: 'Set a breakpoint' },
            { value: '# F9 — Run to breakpoint', description: 'Execute until breakpoint hits' },
            { value: '# F7 — Step into, F8 — Step over', description: 'Step through instructions' },
          ]
        }
      ]
    },
    {
      id: 'assembly',
      title: '⚙️ x86/x64 Assembly Essentials',
      content: [
        {
          type: 'markdown',
          value: `### CPU Registers (x64)

| Register | Purpose |
|----------|---------|
| **RAX** | Return value / accumulator |
| **RBX** | Base (callee-saved) |
| **RCX** | Counter / 1st arg (Windows) |
| **RDX** | Data / 2nd arg (Windows) |
| **RSI** | Source / 2nd arg (Linux) |
| **RDI** | Destination / 1st arg (Linux) |
| **RSP** | Stack pointer (top of stack) |
| **RBP** | Base pointer (stack frame base) |
| **RIP** | Instruction pointer (next instruction) |
| **R8–R15** | General purpose (64-bit only) |

**EFLAGS** — Status bits: ZF (zero), CF (carry), SF (sign), OF (overflow)`
        },
        {
          type: 'markdown',
          value: `### Common Assembly Instructions
\`\`\`asm
; Data movement
mov rax, rbx          ; Copy rbx to rax
mov [rsp+8], rax      ; Store rax at [rsp+8] (memory)
lea rax, [rbx+4]      ; Load address rbx+4 into rax (no memory access)
xchg rax, rbx         ; Swap values
push rax              ; Push rax onto stack
pop rax               ; Pop from stack into rax

; Arithmetic
add rax, rbx          ; rax = rax + rbx
sub rax, 10           ; rax = rax - 10
imul rax, rbx         ; rax = rax * rbx (signed)
div rbx               ; rax = rdx:rax / rbx (quotient in rax, remainder in rdx)
inc rax               ; rax = rax + 1
dec rax               ; rax = rax - 1

; Bitwise
and rax, rbx          ; rax = rax AND rbx (mask bits)
or  rax, rbx          ; rax = rax OR rbx
xor rax, rax          ; rax = 0 (classic way to zero a register)
shl rax, 4            ; Shift left 4 bits (multiply by 16)
shr rax, 2            ; Shift right 2 bits (divide by 4)

; Control flow
cmp rax, rbx          ; Set flags based on rax - rbx (don't store result)
test rax, rax         ; Set flags based on rax AND rax (check if zero)
je  label             ; Jump if equal (ZF=1)
jne label             ; Jump if not equal (ZF=0)
jl  label             ; Jump if less (signed)
jg  label             ; Jump if greater (signed)
jmp label             ; Unconditional jump
call func             ; Call function (push return addr, jmp to func)
ret                   ; Return (pop return addr, jmp to it)
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Reading a Simple Function
\`\`\`asm
; C code: int check_password(char* input) { return strcmp(input, "s3cr3t") == 0; }
; Disassembly:

push   rbp                    ; Save base pointer
mov    rbp, rsp               ; Set up stack frame
sub    rsp, 16                ; Reserve stack space
mov    QWORD PTR [rbp-8], rdi ; Store 'input' arg on stack

; Call strcmp(input, "s3cr3t")
mov    rdi, QWORD PTR [rbp-8] ; 1st arg: input
lea    rsi, [rip+0x100]       ; 2nd arg: "s3cr3t" (address of string literal)
call   strcmp                 ; strcmp(input, "s3cr3t")

; Check return value
test   eax, eax               ; strcmp returns 0 if equal
sete   al                     ; al = 1 if equal (ZF was set), else 0
movzx  eax, al                ; Zero-extend to eax

; This tells us: the password is "s3cr3t"!
leave
ret
\`\`\``
        }
      ]
    },
    {
      id: 'ghidra',
      title: '🔮 Ghidra — NSA Decompiler',
      content: [
        {
          type: 'markdown',
          value: `### Ghidra Quickstart
\`\`\`bash
# Download Ghidra from https://ghidra-sre.org/
# Requires Java 17+
java -version   # Verify Java
./ghidraRun     # Launch (Linux/Mac)
ghidraRun.bat   # Launch (Windows)
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Key Ghidra Features & Shortcuts

| Action | Shortcut |
|--------|---------|
| Search all text | **Ctrl+F** |
| Search for function | **Ctrl+Shift+E** |
| Go to address | **G** |
| Add bookmark | **Ctrl+D** |
| Rename variable/function | **L** |
| Cross-references (XRefs) | **Ctrl+Shift+F** |
| Toggle decompiler | **Ctrl+E** |
| Script manager | **Ctrl+Shift+S** |
| Find strings | *Search > For Strings...* |
| Find constants | *Search > For Scalars...* |`
        },
        {
          type: 'markdown',
          value: `### Ghidra Script Automation
\`\`\`python
# Ghidra Python script (run via Script Manager)
# Find all calls to strcmp — useful for finding hardcoded passwords

from ghidra.program.model.symbol import RefType

def find_strcmp_calls():
    listing = currentProgram.getListing()
    symbol_table = currentProgram.getSymbolTable()
    
    # Find strcmp function
    symbols = symbol_table.getSymbols("strcmp")
    for symbol in symbols:
        strcmp_addr = symbol.getAddress()
        # Get all references to strcmp
        refs = getReferencesTo(strcmp_addr)
        for ref in refs:
            if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                addr = ref.getFromAddress()
                print(f"strcmp called at: {addr}")
                # Look at instruction before call to see what's being compared
                inst = listing.getInstructionAt(addr)
                print(f"  Instruction: {inst}")

find_strcmp_calls()
\`\`\``
        }
      ]
    },
    {
      id: 'gdb',
      title: '🐛 GDB + pwndbg (Linux Debugging)',
      content: [
        {
          type: 'markdown',
          value: `### GDB Setup & Essential Commands
\`\`\`bash
# Install pwndbg (enhanced GDB)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Basic GDB usage
gdb ./binary           # Load binary
gdb ./binary core      # Load binary with core dump

# In GDB:
run arg1 arg2          # Run the program
run < input.txt        # Run with stdin from file
break main             # Set breakpoint at main
break *0x400567        # Set breakpoint at address
break func_name        # Set breakpoint at function
info breakpoints       # List all breakpoints
delete 1               # Delete breakpoint #1

continue               # Continue execution (c)
next                   # Step over (n)
step                   # Step into (s)
ni                     # Next instruction (assembly level)
si                     # Step instruction

# Inspect
info registers         # Show all registers
print $rax             # Print register value
print/x $rax           # Print as hex
x/20xb $rsp            # Examine 20 bytes at RSP in hex
x/s 0x400100           # Examine as string at address
x/10i $rip             # Examine 10 instructions at RIP (disassemble)

# pwndbg specific
context                # Show full context (registers, stack, disasm)
stack                  # Show stack contents
vmmap                  # Show memory map
telescope $rsp 20      # Show 20 stack entries with annotations
\`\`\``
        }
      ]
    },
    {
      id: 'anti-analysis',
      title: '🥷 Anti-Analysis Techniques (Advanced)',
      content: [
        {
          type: 'markdown',
          value: `### Common Anti-Analysis Tricks

| Technique | Detection | Bypass |
|-----------|-----------|--------|
| **IsDebuggerPresent** | Windows API call | Patch return value to 0 |
| **Timing checks** | rdtsc before/after operation | Patch timing code |
| **Anti-VM** | Check for VM artifacts (vmware*, vbox*) | Real hardware or patch |
| **Packing** | UPX, custom packers | Unpack first |
| **Obfuscation** | Junk code, dead code | Simplify in Ghidra |
| **String encryption** | Strings not visible | Set breakpoint after decrypt |`
        },
        {
          type: 'markdown',
          value: `### Unpacking & Defeating Packers
\`\`\`bash
# Detect packing with detect-it-easy
die binary.exe
# or
exeinfo binary.exe

# UPX unpack (most common)
upx -d packed.exe -o unpacked.exe

# Manual unpacking (generic):
# 1. Load packed binary in debugger
# 2. Set breakpoint on EntryPoint (OEP detection)
# 3. Let packer unpack itself into memory
# 4. When it jumps to OEP, dump memory
# 5. Fix imports (IAT rebuilding with Scylla)

# x64dbg: Set hardware breakpoint on new section write
# Then when packer writes unpacked code: dump!

# PE-bear — PE header analyzer
# Helps detect corrupted headers from packing
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Frida for Desktop RE (Anti-debug bypass)
\`\`\`javascript
// Bypass IsDebuggerPresent (Windows)
var IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
Interceptor.attach(IsDebuggerPresent, {
    onLeave: function(retval) {
        retval.replace(0);  // Always return "not debugged"
        console.log('[+] IsDebuggerPresent bypassed');
    }
});

// Hook NtQueryInformationProcess (advanced anti-debug)
var NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
Interceptor.attach(NtQueryInformationProcess, {
    onEnter: function(args) {
        this.ProcessInformationClass = args[1].toInt32();
    },
    onLeave: function(retval) {
        if (this.ProcessInformationClass === 7) {  // ProcessDebugPort
            Memory.writeU32(this.context.rdx, 0);  // Write 0 (no debugger)
        }
    }
});
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaBrain /> Reverse Engineering Cheat Sheet
      </h2>

      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Complete reverse engineering reference from beginner triage (strings, file) through 
          assembly analysis, Ghidra decompilation, GDB/pwndbg debugging, to advanced anti-analysis 
          bypass techniques. Covers Windows PE and Linux ELF binaries.
        </p>
      </div>

      <div className="sections-container">
        {sections.map((section) => (
          <div key={section.id} className="section">
            <motion.div
              className="section-header"
              onClick={() => toggleSection(section.id)}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <h3>{section.title}</h3>
              <motion.div animate={{ rotate: expandedSection === section.id ? 180 : 0 }}>
                <FaChevronDown />
              </motion.div>
            </motion.div>

            <motion.div
              className="section-content"
              initial={{ opacity: 0, height: 0 }}
              animate={{
                opacity: expandedSection === section.id ? 1 : 0,
                height: expandedSection === section.id ? 'auto' : 0
              }}
              transition={{ duration: 0.3 }}
            >
              {expandedSection === section.id && (
                <div className="content-inner">
                  {section.content.map((item, index) => {
                    if (item.type === 'step') {
                      return (
                        <div key={index} className="content-item walkthrough-step">
                          <div className="step-header"><strong>{item.title}</strong></div>
                          <div className="step-description">{item.description}</div>
                          <div className="step-commands">
                            {item.commands.map((cmd, i) => (
                              <div key={i} className="command-item">
                                <div className="command-header">
                                  <code>{cmd.value}</code>
                                  <button onClick={() => handleCopy(cmd.value)} className="copy-button small">Copy</button>
                                </div>
                                <p className="command-description">{cmd.description}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    } else {
                      return (
                        <div key={index} className="content-item">
                          <div className="markdown-content">
                            <ReactMarkdown>{item.value}</ReactMarkdown>
                          </div>
                        </div>
                      );
                    }
                  })}
                </div>
              )}
            </motion.div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ReverseEngineering;
