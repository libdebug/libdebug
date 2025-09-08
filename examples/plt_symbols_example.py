#!/usr/bin/env python3

"""
Example demonstrating PLT symbols in libdebug.

This example shows how PLT symbols can be used to set breakpoints
on dynamic library function calls before they are resolved.
"""

import tempfile
import subprocess
import os

def create_example_binary():
    """Create an example binary that uses several dynamic library functions"""
    example_c = '''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void demonstrate_strcmp() {
    char str1[] = "hello";
    char str2[] = "world";
    
    // This call will go through the PLT
    int result = strcmp(str1, str2);
    printf("strcmp('%s', '%s') = %d\\n", str1, str2, result);
}

int main() {
    printf("=== PLT Symbols Example ===\\n");
    
    // Allocate some memory (malloc PLT call)
    char *buffer = malloc(100);
    if (buffer) {
        // Copy string (strcpy PLT call) 
        strcpy(buffer, "Hello from libdebug!");
        
        // Print the string (printf PLT call)
        printf("Buffer contents: %s\\n", buffer);
        
        // Free the memory (free PLT call)
        free(buffer);
    }
    
    // Demonstrate string comparison
    demonstrate_strcmp();
    
    printf("Program completed.\\n");
    return 0;
}
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(example_c)
        source_file = f.name
    
    binary_file = source_file.replace('.c', '')
    subprocess.run(['gcc', '-O0', '-o', binary_file, source_file], check=True)
    
    os.unlink(source_file)
    return binary_file

def demonstrate_plt_symbols():
    """Demonstrate PLT symbols functionality"""
    binary_path = create_example_binary()
    
    try:
        import libdebug
        
        print("Creating debugger instance...")
        d = libdebug.debugger(binary_path)
        d.run()
        
        print("\\n=== Available PLT Symbols ===")
        
        # Find all PLT symbols
        plt_symbols = [sym for sym in d.symbols if sym.name.startswith('plt@')]
        
        if not plt_symbols:
            print("❌ No PLT symbols found! The feature may not be working.")
            return False
        
        print(f"Found {len(plt_symbols)} PLT symbols:")
        for sym in plt_symbols:
            print(f"  📍 {sym.name:<20} at 0x{sym.start:08x} (size: {sym.end - sym.start})")
        
        # Demonstrate setting breakpoints on PLT symbols
        print("\\n=== Setting Breakpoints on PLT Symbols ===")
        
        breakpoints = []
        for sym in plt_symbols[:3]:  # Set breakpoints on first 3 PLT symbols
            try:
                bp = d.breakpoint(sym.name)
                breakpoints.append((bp, sym.name))
                print(f"✅ Breakpoint set on {sym.name}")
            except Exception as e:
                print(f"❌ Failed to set breakpoint on {sym.name}: {e}")
        
        if breakpoints:
            print(f"\\n🎯 Successfully set {len(breakpoints)} breakpoints on PLT symbols!")
            print("\\nThis demonstrates that PLT symbols can be used for:")
            print("  • Setting breakpoints on dynamic library calls")
            print("  • Intercepting function calls before they reach the actual implementation")
            print("  • Debugging dynamic linking issues")
            print("  • Understanding program control flow through PLT")
        
        # Clean up breakpoints
        for bp, name in breakpoints:
            bp.disable()
        
        d.kill()
        d.terminate()
        
        return len(plt_symbols) > 0
        
    except ImportError:
        print("❌ libdebug not available. Please build and install libdebug first.")
        
        # Show what PLT symbols would be available using objdump
        print("\\n=== Expected PLT Symbols (using objdump) ===")
        result = subprocess.run(['readelf', '-r', binary_path], 
                               capture_output=True, text=True)
        
        print("PLT symbols that would be available with libdebug:")
        in_plt_section = False
        count = 0
        for line in result.stdout.split('\\n'):
            if '.rela.plt' in line:
                in_plt_section = True
                continue
            if in_plt_section and line.strip():
                if line.startswith('Offset') or line.startswith('  Offset'):
                    continue
                if not line.strip() or line.startswith('Relocation'):
                    break
                parts = line.split()
                if len(parts) >= 5:
                    symbol = parts[4].split('@')[0]
                    count += 1
                    print(f"  📍 plt@{symbol}")
        
        print(f"\\nTotal: {count} PLT symbols would be available")
        return False
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
        
    finally:
        if os.path.exists(binary_path):
            os.unlink(binary_path)

if __name__ == "__main__":
    print("🔍 PLT Symbols Example for libdebug")
    print("=" * 50)
    
    success = demonstrate_plt_symbols()
    
    if success:
        print("\\n🎉 PLT symbols example completed successfully!")
    else:
        print("\\n📝 Build libdebug to see PLT symbols in action!")
        print("\\nPLT symbols allow you to:")
        print("  • Set breakpoints on 'plt@strcmp' instead of guessing '__strcmp_avx2'")
        print("  • Catch dynamic library calls before resolution") 
        print("  • Debug linking and loading issues")
        print("  • Understand program flow through the PLT")