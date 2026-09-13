# This is a shellcode extraction tool. All it does is dump the .text section
# of an executable to the screen in a C style array with 16 byte format alignment.
# 
# You must compile/assemble your executable to contain the shellcode in the .text
# section. This tool does not do that for you.
#
# wizardy0ga - aug 2026 
#
import pefile
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Must supply path to executable.")
        exit(1)
    
    text_section_data = None
    try:
        pe = pefile.PE(sys.argv[1])
        for section in pe.sections:
            if section.Name.startswith(b'.text'):
                text_section_data = section.get_data()
                break

        if not text_section_data:
            print("Failed to get the .text section!")
            exit(1)
            
        print("char shellcode[] = {")
        end_of_code = False
        for i, byte in enumerate(text_section_data):
            if end_of_code is True:
                break
            
            # Remove trailing nullbytes & software interrupts (if debug mode was enabled)
            # By checking ahead 8 bytes to see if they are all 0x0 or 0xCC. If so we end the code.
            for opcode in ['0x0', '0xcc']:
                for j in range(0, 8):
                    if hex(text_section_data[i:][j]) != opcode:
                        break
                    if j == 7:
                        end_of_code = True 

            if i % 16 == 0:
                if i != 0:
                    print(",")
                print("    ", end="")
            else:
                print(", ", end="")
                
            print(f"0x{byte:02X}", end="")
        
        print("\n};")
        
    except Exception as e:
        print(f"Operation failed with error: {e}")
        exit(1)