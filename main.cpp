#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <cctype>
#include "TrapdoorPatterns.h"  // 👈 Include the external pattern module

using namespace std;

class VulnerabilityDetector {
    set<string> vulnerabilities;
    set<string> uniqueSuggestions;

public:
    void menu() {
        int choice;
        while (true) {
            cout << "\n=== Security Vulnerability Detection ===\n";
            cout << "1. Buffer Overflow Check\n";
            cout << "2. Trapdoor Detection\n";
            cout << "3. Command Injection Check\n";
            cout << "4. Weak Password Check\n";
            cout << "5. Show Results\n";
            cout << "6. Cache Poisoning Check\n";
            cout << "0. Exit\n";
            cout << "Enter your choice: ";
            cin >> choice;
            cin.ignore();

            if (choice == 0) break;

            switch (choice) {
                case 1: bufferOverflowTest(); break;
                case 2: trapdoorTest(); break;
                case 3: commandInjectionTest(); break;
                case 4: passwordTest(); break;
                case 5: printResults(); break;
                case 6: cachePoisoningTest(); break;
                default: cout << "❌ Invalid choice. Try again.\n";
            }
        }
    }

    void bufferOverflowTest() {
        int bufferSize;
        string input;
        cout << "\n[Buffer Overflow Test]\n";
        cout << "Enter buffer size: ";
        while (!(cin >> bufferSize) || bufferSize <= 0) {
            cout << "❌ Invalid input. Enter a positive number: ";
            cin.clear();
            cin.ignore(1000, '\n');
        }

        cin.ignore();
        cout << "Enter test string: ";
        getline(cin, input);

        if ((int)input.length() > bufferSize) {
            vulnerabilities.insert("Buffer overflow detected!");
            uniqueSuggestions.insert("Use safe string handling like std::string.");
        } else {
            cout << "✅ No buffer overflow detected.\n";
        }
    }

    void trapdoorTest() {
        string code;
        cout << "\n[Trapdoor Detection]\nPaste code or string: ";
        getline(cin, code);

        bool found = false;
        for (const string& pattern : trapdoorPatterns) {
            if (code.find(pattern) != string::npos) {
                vulnerabilities.insert("Trapdoor detected!");
                uniqueSuggestions.insert("Avoid hardcoded credentials or suspicious OS-level code.");
                found = true;
                break;
            }
        }

        if (!found) {
            cout << "✅ No trapdoor detected.\n";
        }
    }

    void commandInjectionTest() {
        string input;
        cout << "\n[Command Injection Check]\nEnter command input: ";
        getline(cin, input);

        if (input.find(";") != string::npos || input.find("&&") != string::npos || input.find("|") != string::npos) {
            vulnerabilities.insert("Command injection risk detected!");
            uniqueSuggestions.insert("Sanitize inputs before passing to system calls.");
        } else {
            cout << "✅ No command injection detected.\n";
        }
    }

    void passwordTest() {
        string pwd;
        cout << "\n[Weak Password Check]\nEnter a password: ";
        getline(cin, pwd);

        bool hasDigit = false, hasUpper = false, hasSymbol = false;
        for (char c : pwd) {
            if (isdigit(c)) hasDigit = true;
            if (isupper(c)) hasUpper = true;
            if (ispunct(c)) hasSymbol = true;
        }

        if (pwd.length() < 8 || !hasDigit || !hasUpper || !hasSymbol ||
            pwd == "123456" || pwd == "password" || pwd == "admin") {
            vulnerabilities.insert("Weak password detected!");
            uniqueSuggestions.insert("Use strong passwords (length > 8, symbols, digits, uppercase).");
        } else {
            cout << "✅ Password looks strong.\n";
        }
    }

    void cachePoisoningTest() {
        string header;
        cout << "\n[Cache Poisoning Check]\n";
        cout << "Enter suspicious header (e.g., Host, X-Forwarded-Host): ";
        getline(cin, header);

        if (header.find("X-Forwarded-Host") != string::npos || header.find("Host:") != string::npos) {
            vulnerabilities.insert("Cache poisoning risk detected!");
            uniqueSuggestions.insert("Validate and normalize headers like Host and X-Forwarded-Host before caching.");
        } else {
            cout << "✅ No cache poisoning risk detected in header.\n";
        }
    }

    void printResults() {
        cout << "\n=== Scan Results ===\n";
        if (vulnerabilities.empty()) {
            cout << "🎉 No vulnerabilities found.\n";
        } else {
            for (const auto& v : vulnerabilities) {
                cout << "- " << v << endl;
            }
            if (!uniqueSuggestions.empty()) {
                cout << "\nSuggestions:\n";
                for (const auto& s : uniqueSuggestions) {
                    cout << "- " << s << endl;
                }
            }
        }
    }
};

int main() {
    VulnerabilityDetector vd;
    vd.menu();
    return 0;
}
