# Reverse Engineering
A set of tools for software reverse engineering.<br>
In the following tables, you can find the tools you need according to the heading


## Debugging
<i>Debugging Tools</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| WinDbg | The WDK is used to develop, test, and deploy Windows drivers. | [Download](https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx) |
| OllyDbg v1.10 | OllyDbg is a 32-bit assembler level analysing debugger for Microsoft® Windows®. Emphasis on binary code analysis makes it particularly useful in cases where source is unavailable. | [Download](http://www.ollydbg.de/) |
| OllyDbg v2.01 | OllyDbg (named after its author, Oleh Yuschuk) is an x86 debugger that emphasizes binary code analysis, which is useful when source code is not available. |[Download](http://www.ollydbg.de/version2.html) |
| x64dbg | An open-source x64/x32 debugger for windows. | [Download](http://x64dbg.com/#start) |
| gdb | GDB, the GNU Project debugger, allows you to see what is going on `inside` another program while it executes -- or what another program was doing at the moment it crashed. | [Download](https://www.gnu.org/software/gdb/) |
| vdb | A combined disassembler/static analysis/symbolic execution/debugger framework. More documentation is in the works. | [github](https://github.com/vivisect/vivisect) |
| lldb | LLDB is a next generation, high-performance debugger. It is built as a set of reusable components which highly leverage existing libraries in the larger LLVM Project, such as the Clang expression parser and LLVM disassembler. | [Download](http://lldb.llvm.org/) |
| qira | All state is tracked while a program is running, so you can debug in the past. | [Download](http://qira.me/) |
| unicorn | Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, X86). | [github](https://github.com/unicorn-engine/unicorn) |

## Disassemblers
<i>Disassemblers</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| IDA Pro | IDA Pro as a disassembler is capable of creating maps of their execution to show the binary instructions that are actually executed by the processor in a symbolic representation (assembly language). | [Download](https://www.hex-rays.com/products/ida/index.shtml) |
| GHIDRA | A software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission. | [Download](https://ghidra-sre.org/) |
| Binary Ninja | Our built-in decompiler works with all our architectures at one price and builds on a powerful family of ILs called BNIL. | [Download](https://binary.ninja/) |
| Radare | Disassemble (and assemble for) many different architectures. | [Download](http://www.radare.org/r/) |
| Hopper | Hopper Disassembler, the reverse engineering tool that lets you disassemble, decompile and debug your applications. | [Download](http://hopperapp.com/) |
| objdump | objdump displays information about one or more object files. The options control what particular information to display. | [Download](http://linux.die.net/man/1/objdump) |
| fREedom | capstone based disassembler for extracting to binnavi. | [Download](https://github.com/cseagle/fREedom) |

## Android
<i>Android tools</i>
| name  | Description | Download | 
| ----- | ----------- | -------- |
| Android Studio | Android Studio provides the fastest tools for building apps on every type of Android device. | [Download](http://developer.android.com/sdk/index.html) |
| APKtool | A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications. | [Download](https://ibotpeaches.github.io/Apktool/) |
| dex2jar | Tools to work with android .dex and java .class files. | [github](https://github.com/pxb1988/dex2jar) |
| IDA Pro | IDA Pro as a disassembler is capable of creating maps of their execution to show the binary instructions that are actually executed by the processor in a symbolic representation (assembly language). | [Download](https://hex-rays.com/ida-pro/) |
| JaDx | Dex to Java decompiler. | [github](https://github.com/skylot/jadx) |

## Hex Editors
<i>Hex Editors</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| HxD | HxD is a carefully designed and fast hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size. | [Download](https://mh-nexus.de/en/hxd/) |
| 010 Editor | Why is 010 Editor so powerful? Unlike traditional hex editors which only display the raw hex bytes of a file.  | [Download](https://www.sweetscape.com/010editor/) |
| Hex Workshop | The Hex Workshop Hex Editor is a set of hexadecimal development tools for Microsoft Windows, combining advanced binary editing with the ease and flexibility of a word processor. | [Download](http://www.hexworkshop.com/) |
| HexFiend | A fast and clever open source hex editor for macOS. | [Download](https://hexfiend.com/) |
| Hiew | view and edit files of any length in text, hex, and decode modes. | [Download](http://www.hiew.ru/) |
| hecate | 🔥 The Hex Editor From Hell! 🔥 | [github](https://github.com/evanmiller/hecate) |

## Binary Format
<i>Binary Format Tools</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| Cerbero Profiler | Inspecting a file is a primary task for every low-level professional, be it for reversing, malware triage, forensics or software development | [Download](https://cerbero.io/) |
| Detect It Easy | Detect It Easy, or abbreviated “DIE” is a program for determining types of files. | [Download](https://horsicq.github.io/) |
| MachoView | MachOView is a visual Mach-O file browser. It provides a complete solution for exploring and in-place editing Intel and ARM binaries. | [Download](http://sourceforge.net/projects/machoview/) |
| codesign | Code signing information usage: codesign -dvvv filename | [Download](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/codesign.1.html) |

## Binary Analysis
<i>Binary Analysis Resources</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| Mobius Resources | Unpacking Virtualization Obfuscators | [Download](https://www.msreverseengineering.com/research/) |
| bap | The Carnegie Mellon University Binary Analysis Platform (CMU BAP) is a suite of utilities and libraries that enables analysis of programs in the machine code representation. | [github](https://github.com/BinaryAnalysisPlatform/bap) |
| angr | angr is a platform-agnostic binary analysis framework. | [github](https://github.com/angr/angr) |

## Bytecode Analysis
<i>Bytecode Analysis Tools</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| dnSpy | dnSpy is a debugger and .NET assembly editor | [github](https://github.com/dnSpy/dnSpy) |
| Bytecode Viewer | SIX DIFFERENT JAVA DECOMPILERS, TWO BYTECODE EDITORS, A JAVA COMPILER,PLUGINS, SEARCHING, SUPPORTS LOADING FROM CLASSES, JARS, ANDROID APKS AND MORE. | [Download](https://bytecodeviewer.com/) |
| JPEXS Free Flash Decompiler | Opensource flash SWF decompiler and editor. | [github](https://github.com/jindrapetrik/jpexs-decompiler) |

## Dynamic Analysis
<i>Dynamic Analysis Tools</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| Process Explorer v16.42 | Process Explorer shows you information about which handles and DLLs processes have opened or loaded. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) |
| Process Monitor v3.82 | Process Monitor is an advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) |
| Autoruns for Windows v13.100 | This utility, which has the most comprehensive knowledge of auto-starting locations of any startup monitor. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) |
| Noriben | Noriben is a Python-based script that works in conjunction with Sysinternals Procmon to automatically collect, analyze, and report on runtime indicators of malware. | [github](https://github.com/Rurik/Noriben) |
| API Monitor | API Monitor is a free software that lets you monitor and control API calls made by applications and services. | [Download](http://www.rohitab.com/apimonitor) |
| INetSim | INetSim is a software suite for simulating common internet services in a lab environment, e.g. for analyzing the network behaviour of unknown malware samples. | [Download](https://www.inetsim.org/) |
| SmartSniff | SmartSniff is a network monitoring utility that allows you to capture TCP/IP packets that pass through your network adapter. | [Download](http://www.nirsoft.net/utils/smsniff.html) |
| TCPView | TCPView is a Windows program that will show you detailed listings of all TCP and UDP endpoints on your system, including the local and remote addresses and state of TCP connections. | [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview) |
| Wireshark | Wireshark is the world’s foremost and widely-used network protocol analyzer. | [Download](https://www.wireshark.org/download.html) |
| Fakenet | FakeNet is a tool that aids in the dynamic analysis of malicious software. | [Download](https://practicalmalwareanalysis.com/fakenet/) |
| Volatility | An advanced memory forensics framework. | [github](https://github.com/volatilityfoundation/volatility) |
| LiME | A Loadable Kernel Module (LKM) which allows for volatile memory acquisition from Linux and Linux-based devices. | [github](https://github.com/504ensicsLabs/LiME) |
| Cuckoo | Cuckoo Sandbox is the leading open source automated malware analysis system. | [Download](https://cuckoosandbox.org/) |
| Objective-See Utilities | Free Mac Security Tools | [Download](https://objective-see.com/products.html) |
| XCode Instruments | XCode Instruments for Monitoring Files and Processes User Guide | [Download](https://developer.apple.com/xcode/download/) |
| fs_usage | report system calls and page faults related to filesystem activity in real-time. File I/O: fs_usage -w -f filesystem | [Download](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/fs_usage.1.html) |
| dmesg | display the system message buffer | [Download](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/dmesg.8.html) |

## Document Analysis
<i>Document Analysis Tools</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| Ole Tools | python-oletools is a package of python tools to analyze Microsoft OLE2 files. | [Download](http://www.decalage.info/python/oletools) |
| Didier's PDF Tools | This tool will parse a PDF document to identify the fundamental elements used in the analyzed file. | [Download](https://blog.didierstevens.com/programs/pdf-tools/) |
| Origami | Origami is a Ruby framework designed to parse, analyze, and forge PDF documents. | [github](https://github.com/cogent/origami-pdf) |

## Scripting
<i>Scripting</i>

| name  | Description | Download | 
| ----- | ----------- | -------- |
| IDA Python Src | IDAPython project for Hex-Ray's IDA Pro. | [github](https://github.com/idapython/src) |
| IDC Functions Doc | The following conventions are used in the function descriptions. | [Download](https://hex-rays.com/products/ida/support/idadoc/162.shtml) |
| IDA Plugin Contest | Hex-Rays Plugin Contest 2021 is now officially started. | [Download](https://hex-rays.com/contests/) |
| onehawt IDA Plugin List | A list of IDA Plugins. | [github](https://github.com/onethawt/idaplugins-list) |
| pefile | pefile is a multi-platform Python module to parse and work with Portable Executable (PE) files. Most of the information contained in the PE file headers is accessible, as well as all the sections' details and data. | [github](https://github.com/erocarrera/pefile) |

## 📔 Reverse Engineering Books

| name  | Description |
| ----- | ----------- |
| The IDA Pro Book  | [Description](http://amzn.to/2jTicOg)  |
| Radare2 Book  | [github page](https://www.gitbook.com/book/radare/radare2book/details)  |
| Reverse Engineering for Beginners | [Description](http://beginners.re/) |
| The Art of Memory Forensics | [Description](http://amzn.to/2jMJQs0) |
| Art of Software Security Assessment | [Description](http://amzn.to/2jlvtyt) |
| iOS Reverse Engineering | [Description](https://github.com/iosre/iOSAppReverseEngineering) |

# 📎 Target and Practice

| name  | Description |
| ----- | ----------- |
| OSX Crackmes | [Description](https://reverse.put.as/crackmes/) |
| ESET Challenges | [Description](http://www.joineset.com/jobs-analyst.html) |
| Flare-on Challenges | [Description](http://flare-on.com/) |
| Github CTF Archives | [github page](http://github.com/ctfs/) |
| Reverse Engineering Challenges | [Description](http://challenges.re/) |
| Malware Blacklist | [Description](http://www.malwareblacklist.com/showMDL.php) |
| malwr.com | [Description](https://malwr.com/) |
