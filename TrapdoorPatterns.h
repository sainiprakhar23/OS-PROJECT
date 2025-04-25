// TrapdoorPatterns.h
#ifndef TRAPDOOR_PATTERNS_H
#define TRAPDOOR_PATTERNS_H

#include <vector>
#include <string>

const std::vector<std::string> trapdoorPatterns = {
    // Credentials & Defaults
    "admin", "root", "12345", "password", "guest", "toor", "qwerty", "letmein", 
    "pass123", "user:pass", "default", "changeme", "secret", "hidden_login",

    // OS-specific patterns (Linux/Unix)
    "setuid(0)", "system(", "popen(", "fork()", "exec(", "/bin/sh", "/bin/bash", 
    "crontab", "rc.local", "LD_PRELOAD", "LD_LIBRARY_PATH", 
    "iptables -F", "chmod 777", "adduser", "useradd", "sudo su",

    // Windows-specific
    "CreateProcess", "WinExec", "ShellExecute", "cmd.exe", "net user", "net localgroup",
    "RunAs", "WMIC", "PowerShell", "rundll32", "reg add", "regedit", "at.exe", "schtasks",

    // Suspicious logic
    "if (user ==", "if (username ==", "if (password ==", "if (ip ==", "if (admin)", 
    "if (role == \"super\")", "bypass", "accessGranted", "backdoor", "hidden_access", 
    "debug_override", "authentication=false", "unreachable_code", 

    // Networking/Remote Shell
    "nc -lvp", "netcat", "reverse shell", "listener", "connect-back", 
    "socket(AF_INET", "127.0.0.1", "localhost", "backconnect", "telnet", "bind shell",

    // Persistence & Malware Indicators
    "startup folder", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
    ".bashrc", ".bash_profile", "init.d", "services.msc", "schtasks", "rc.d", 
    "Registry\\Run", "cronjob", "initctl",

    // Hardcoded Paths and IPs
    "C:\\", "/etc/", "/usr/bin", "192.168.", "10.0.", "localhost", "::1",

    // Code Injection / Eval
    "eval(", "base64_decode(", "exec(", "compile(", "marshal.loads", "unpickle(", 
    "shellcode", "NOP sled", "jmp esp",

    // Encoded Payloads or Obfuscation
    "0x90", "\\x90", "xor encoded", "base64", "rot13", "hex encoded payload",

    // Toolkits & Exploits (Detection Markers)
    "Metasploit", "Empire", "Cobalt Strike", "Mimikatz", "Veil", "Pupy", "Nishang", 
    "Netcat", "C2", "Command and Control", "payload.exe", "dllinject", "dropshell"
};

#endif // TRAPDOOR_PATTERNS_H
