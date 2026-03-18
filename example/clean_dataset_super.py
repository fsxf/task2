import os
import subprocess
import re
import argparse
import tempfile

def process_file(filepath, output_dir, gcc_marker_pattern, comment_pattern):
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1] # 获取后缀是 .c 还是 .cpp
    out_filepath = os.path.join(output_dir, filename)
    print(f"Processing: {filename}")
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        raw_code = f.read()

    sys_include_pattern = re.compile(r'^\s*#\s*include\s*<.*?>\s*$', re.MULTILINE)
    code_without_sys_includes = sys_include_pattern.sub('', raw_code)

    fd, temp_path = tempfile.mkstemp(suffix=ext, text=True)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(code_without_sys_includes)

    original_dir = os.path.dirname(os.path.abspath(filepath))
    # 智能切换编译器
    compiler = "g++" if ext == '.cpp' else "gcc"
    cmd = [compiler, "-E", temp_path, "-I", original_dir]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        code = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] {compiler.upper()} Error on {filename}. Skipping.\nError details: {e.stderr}")
        os.remove(temp_path)
        return

    os.remove(temp_path)

    code = gcc_marker_pattern.sub('', code)
    code = comment_pattern.sub('', code)
    
    code = re.sub(r'CWE\d+_[a-zA-Z0-9_]+_(\d+[a-zA-Z]*)_', r'target_func_\1_', code)
    code = code.replace('badSink', 'process_data').replace('bad', 'start_workflow')
    code = code.replace('goodG2B', 'safe_flow_A').replace('goodB2G', 'safe_flow_B').replace('good', 'alt_workflow')

    code = os.linesep.join([s for s in code.splitlines() if s.strip()])

    with open(out_filepath, 'w', encoding='utf-8') as f:
        f.write(code)

def clean_and_sanitize(input_path, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    gcc_marker_pattern = re.compile(r'^#\s+\d+\s+.*$', re.MULTILINE)
    comment_pattern = re.compile(r'//.*?$|/\*.*?\*/', re.MULTILINE | re.DOTALL)

    if os.path.isdir(input_path):
        for filename in os.listdir(input_path):
            # 兼容 .c 和 .cpp
            if not (filename.endswith('.c') or filename.endswith('.cpp')):
                continue
            filepath = os.path.join(input_path, filename)
            process_file(filepath, output_dir, gcc_marker_pattern, comment_pattern)
            
    print(f"\n✅ Processing complete. Cleaned files saved to: {output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Preprocess and sanitize C/C++ dataset.")
    parser.add_argument("input_path", help="Directory containing raw .c or .cpp files")
    parser.add_argument("output_dir", help="Directory to save cleaned files")
    args = parser.parse_args()
    clean_and_sanitize(args.input_path, args.output_dir)