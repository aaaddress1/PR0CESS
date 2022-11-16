import argparse
import csv
import os
from time import sleep
from concurrent.futures import ThreadPoolExecutor
import threading
CSVLock = threading.Lock()


def valid_member(symbols_info, symbol_name_index):
    struct_finish = "};"
    while struct_finish not in symbols_info[symbol_name_index]:
        symbol_name_index -= 1
    return symbols_info[symbol_name_index + 1]


def symbols_offsets_extract(symbols_info, symbol_name):
    for line in symbols_info:
        if line.strip().split(" ")[-1].endswith(symbol_name):
            return int(line.split(" ")[0], 16)
    else:
        return 0


def fields_offsets_extract(symbols_info, field_name):
    for line in range(0, len(symbols_info)):
        if "_LIST_ENTRY ThreadListHead" in symbols_info[line] and "struct _EPROCESS {" not in valid_member(symbols_info, line):
            continue
        if "_KTRAP_FRAME* TrapFrame" in symbols_info[line] and "struct _KTHREAD {" not in valid_member(symbols_info, line):
            continue
        if "uint64_t Rip" in symbols_info[line] and "struct _KTRAP_FRAME {" not in valid_member(symbols_info, line):
            continue
        if "_LIST_ENTRY ThreadListEntry" in symbols_info[line] and "struct _ETHREAD {" not in valid_member(symbols_info, line):
            continue
        if "_GUID Guid" in symbols_info[line] and "struct _ETW_GUID_ENTRY {" not in valid_member(symbols_info, line):
            continue
        if field_name in symbols_info[line]:
            assert "offset" in symbols_info[line]
            symbol_offset = int(symbols_info[line].split("+")[-1], 16)
            return symbol_offset
    else:
        return 0


def ntos_version(path):
    r = os.popen(f"r2 -c iV -qq {path}")
    for line in r.read().splitlines():
        line = line.strip()
        if line.startswith("FileVersion:"):
            return [int(frag) for frag in line.split(" ")[-1].split(".")]

    print(f'[!] ERROR : failed to extract version from {path}.')
    raise RuntimeError("get_file_version error")


def offsets_extraction_routine(input_file, mode):
    output_file = "NtoskrnlCSV.csv"
    if os.path.isfile(input_file):
        try:
            r = os.popen(f"r2 -c iE -qq {input_file}")
            for line in r.read().splitlines():
                if "ntoskrnl.exe" in line:
                    imageType = "ntoskrnl"
                    break
            else:
                print(f"[*] File {input_file} unrecognized")
                return

            if mode != imageType:
                print(f"[*] Skipping {input_file} since we are in {mode} mode")
                return
            if os.path.sep not in input_file:
                input_file = "." + os.path.sep + input_file
            full_version = ntos_version(input_file)

            extension = "exe"
            imageVersion = f'{imageType}_{full_version[2]}-{full_version[3]}.{extension}'

            print(f'[*] Processing {imageType} version {imageVersion} (file: {input_file})')
            # download the PDB and dump all symbols
            r = os.popen(f"r2 -c idpd -qq {input_file}")
            # wait until download will be finished
            if ("ntkrnlmp.pdb" not in r.read()):
                print("[+] Can't download pdb file")
                exit(1)
            r = os.popen(f"r2 -c idpi -qq -B 0 {input_file}")
            all_symbols_info = [line.strip() for line in r.read().splitlines()]

            symbols = [("_LIST_ENTRY ActiveProcessLinks", fields_offsets_extract),
                       ("void * UniqueProcessId", fields_offsets_extract),
                       ("_LIST_ENTRY ThreadListHead", fields_offsets_extract),
                       ("_PS_PROTECTION Protection", fields_offsets_extract),
                       ("_EX_FAST_REF Token", fields_offsets_extract),
                       ("_HANDLE_TABLE* ObjectTable", fields_offsets_extract),
                       ('_KTRAP_FRAME* TrapFrame', fields_offsets_extract),
                       ("uint64_t Rip", fields_offsets_extract),
                       ("_LIST_ENTRY ThreadListEntry", fields_offsets_extract),
                       ("_CLIENT_ID Cid", fields_offsets_extract),
                       ("EtwThreatIntProvRegHandle", symbols_offsets_extract),
                       ("_ETW_GUID_ENTRY* GuidEntry", fields_offsets_extract),
                       ("_TRACE_ENABLE_INFO ProviderEnableInfo", fields_offsets_extract),
                       ("_GUID Guid", fields_offsets_extract)]

            symbols_values = list()
            for symbol_name, get_offset in symbols:
                symbol_value = get_offset(all_symbols_info, symbol_name)
                symbols_values.append(symbol_value)
                print(f"[+] {symbol_name} = {hex(symbol_value)}")

            with CSVLock:
                with open(output_file, 'a') as output:
                    output.write(f'SOF,{",".join(hex(val).replace("0x", "") for val in symbols_values)}\n')

            print(f'[+] CSV ready')

        except Exception as e:
            print(f'[!] ERROR : Could not process file {input_file}.')
            print(f'[!] Error message: {e} {e.with_traceback()}')
            print(
                f'[!] If error is of the like of "\'NoneType\' object has no attribute \'group\'", kernel callbacks may not be supported by this version.')

    elif os.path.isdir(input_file):
        print(f'[*] Processing folder: {input_file}')
        with ThreadPoolExecutor() as extractorPool:
            args = [(os.path.join(input_file, file), output_file, mode) for file in os.listdir(input_file)]
            for (i, res) in enumerate(extractorPool.map(offsets_extraction_routine, *zip(*args))):
                print(f"{i + 1}/{len(args)}", end="\r")
        print(f'[+] Finished processing of folder {input_file}!')

    else:
        print(f'[!] ERROR : The specified input {input_file} is neither a file nor a directory.')


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', dest='input', required=True,
                        help='Single file or directory containing ntoskrnl.exe / wdigest.dll to extract offsets from. If in download mode, the PE downloaded from MS symbols servers will be placed in this folder.')

    args = parser.parse_args()
    mode = "ntoskrnl"

    r = os.popen("r2 -V")
    if r.errors != 'strict':
        print(f"Error: the following error message was printed while running 'r2 -V': {r.errors}")
        exit(1)
    output = r.read()
    ntosk, ver, build = map(int, output.splitlines()[0].split(" ")[0].split("."))

    if (ntosk, ver, build) < (5, 0, 0):
        print("WARNING : This script has been tested with radare2 5.0.0 (works) and 4.3.1 (does NOT work)")
        print(
            f"You have version {ntosk}.{ver}.{build}, if is does not work correctly, meaning most of the offsets are not found (i.e. 0), check radare2's 'idpi' command output and modify get_symbol_offset() & get_field_offset() to parse symbols correctly")
        input("Press enter to continue")

    with open("NtoskrnlCSV.csv", 'w') as output:
        output.write(
            'SMark,ActiveProcessLinks,UniqueProcessId,ThreadListHead,'
            'Protection,Token,ObjectTable,TrapFrame,Rip,ThreadListEntry,Cid,'
            'EtwThreatIntProvRegHandle,GuidEntry,ProviderEnableInfo,Guid\n')

    offsets_extraction_routine(args.input, mode)

