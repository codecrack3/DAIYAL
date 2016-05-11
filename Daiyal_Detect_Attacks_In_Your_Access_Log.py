#-*-coding: utf-8 -*-
__author__ = 'jb93lee'

log_file_name = 'access_log' # 로그 파일명을 입력합니다. 해당 로그는 동일 폴더 내에 존재해야 합니다.
index = 'IIS2' # 로그 파일 포맷에 맞는 인덱스 값을 적어줍니다.
suspect_ip = 'input suspect_ip in here' # 따로 추출하고 싶은 IP가 있다면 여기에 입력합니다.
ignore_word = ['select_arrange','another_string'] # 무시하고 싶은 문자열이 있다면 리스트에 추가해줍니다.

# 로그 파일 포맷이 맞지 않는다면 새로 생성하셔야 합니다. 대부분의 로그 포맷은 아래 중 하나입니다.
if index == 'IIS1':
    http_method = -2
    request_code = -5
    url = -1
elif index == 'IIS2':
    http_method = 5
    request_code = 8
    url = 6
elif index == 'Apache':
    http_method = 4
    request_code = -3
    url = 5

# 로그파일들은 아래와 같이 분류되어 저장됩니다.
file1 = open('suspect_log_warn.txt', 'wb')
file2 = open('suspect_log_alert.txt', 'wb')
file3 = open('suspect_log_ip.txt', 'wb')

# 로그파일 내 공격이 의심되는 로그를 추출합니다.
for line in open(log_file_name, 'rb'):
    if '#' in line:
        continue
    if line.strip() == '':
        continue
    if suspect_ip in line: # Extract by ip
        file3.write(line)
    for i in range(len(ignore_word)): # ignore
        if ignore_word[i] in line:
            continue
    fields = line.split()
    if 'HEAD' in fields[http_method].upper(): # Scanning
        file1.write(line)
    if 'POST' in fields[http_method].upper():
        file2.write(line)
    if 'EDIT' in fields[request_code].upper(): # Edit File
        file1.write(line)
    if '404' in fields[request_code].upper():
        file1.write(line)
    elif 'PUT' in fields[http_method].upper(): # Upload File
        file2.write(line)
    elif 'DELETE' in fields[http_method].upper(): # Delete File
        file2.write(line)
    elif 'HEAD' in fields[http_method].upper(): # Scan Success
        if '20' in fields[request_code]:
            file2.write(line)
    elif 'SHELL' in fields[url].upper(): # WebShell Upload
        file2.write(line)
    elif 'CMD' in fields[url].upper():
        file2.write(line)
    elif 'UPLOAD' in fields[url].upper():
        file2.write(line)
    elif ';' in fields[url]:
        file2.write(line)
    elif '%00' in fields[url]:
        file2.write(line)
    elif '..' in fields[url]: # Directory Listing, File Download
        file2.write(line)
    elif 'SELECT' in fields[url].upper(): # SQL Injection
        file2.write(line)
    elif 'UNION' in fields[url].upper():
        file2.write(line)
    elif 'HTTP://' in fields[url].upper(): # RFI, XSS, Redirect
        file2.write(line)
    elif 'PASSWD' in fields[url].upper():
        file2.write(line)
    elif 'DOCUMENT.' in fields[url].upper(): # XSS
        file2.write(line)
    elif 'CMD=' in fields[url].upper(): # Command Injection
        file2.write(line)
    elif 'WGET%20' in fields[url].upper(): # Download
        file2.write(line)
    else:
        pass

file1.close()
file2.close()
file3.close()
