from port.filecheck import filecheck
import os
import argparse


def check_file_path(file_path):
    # 检查文件路径是否存在
    if os.path.exists(file_path):
        print("文件路径存在。")
        filecheck(file_path)
    else:
        print("文件路径不存在。")

if __name__ == "__main__":
    # 设置命令行参数
    parser = argparse.ArgumentParser(description="检测文件路径是否存在")
    parser.add_argument("file_path", type=str, help="输入要检测的文件路径")
    
    # 解析参数
    args = parser.parse_args()
    
    # 调用检测函数
    check_file_path(args.file_path)
