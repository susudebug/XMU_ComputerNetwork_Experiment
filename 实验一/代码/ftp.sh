#!/bin/bash

# 解析命令行参数
while getopts ":a:b:c:s:t:" opt; do
  case $opt in
    a) ftp_server_address=$OPTARG;;
    b) ftp_account=$OPTARG;;
    c) operation=$OPTARG;;
    s) source_file=$OPTARG;;
    t) target_path=$OPTARG;;
    \?) echo "Invalid option -$OPTARG" >&2;;
  esac
done

# 根据操作进行相应的操作
case $operation in
  "upload")
    echo "Uploading file $source_file to $target_path on $ftp_server_address..."
    ftp -n $ftp_server_address<<EOF
    user $ftp_account
    lcd $target_path
    put $source_file
    bye
EOF
    ;;
  "download")
    echo "Downloading file $source_file from $target_path on $ftp_server_address to local..."
    ftp -n $ftp_server_address<<EOF
    user $ftp_account
    lcd $target_path
    get $source_file
    bye
EOF
    ;;
  "delete")
    echo "Deleting file $source_file on $ftp_server_address..."
    ftp -n $ftp_server_address<<EOF
    user $ftp_account
    delete $source_file
    bye
EOF
    ;;
  "view")
    echo "Deleting file $source_file on $ftp_server_address..."
    ftp -n $ftp_server_address<<EOF
    user $ftp_account
    ls
    bye
EOF
    ;;

  *)
    echo "Invalid operation: $operation. Supported operations: upload, download, delete."
    exit 1
    ;;
esac
