import zono.zonocrypt as zonocrypt
import os
import clipboard
import zipfile
import shutil
import time
import subprocess
import zono.colorlogger as cl


__all__ = ['-of', '-i', '-replace', '-pass', '-passgen',
           '-key', '-archive', '-info', '-help', '?']


__help__ = """ef encrypts files or folders using SHA512 encryption
-of        changes the output file
-i         ignores all warnings
-replace   replaces the input file
-pass      provide a string password which is later turned in to a secure b64 encoded key
-passgen   Utilise the hashing algorithm to generate a 32 long b64 encoded key which can be used with this tool
-key       provide a base64 encoded 32 long key
-archive   Compresses input file to reduce file size
-info      displays extra information about the encrypted file
-help/?    displays this message"""

crypt = zonocrypt.zonocrypt()


def hide_dir(Dir):
    subprocess.check_call(['attrib', '+H', Dir])


def zip_dir(path):
    zf = zipfile.ZipFile('{}.zip'.format(path), 'w', zipfile.ZIP_DEFLATED)

    for root, dirs, files in os.walk(path):
        for file_name in files:
            zf.write(os.path.join(root, file_name))


def unzip(path):
    with zipfile.ZipFile(path, 'r') as ZIP:
        ZIP.extractall()


def main(ctx):
    output_file = 'enc_file.encrypted'

    args = ctx.args.split(' ')
    if ctx.args == ' ' or ctx.args == '':
        args = []

    if '?' in args or '-help' in args:
        print(__help__)
        return

    INFO = False
    if '-info' in args:
        INFO = True
        start_time = time.time()

    if '-pass' in args and '-key' in args:
        print('-pass and -key cannot be used together')
        return

    if '-passgen' in args:
        try:
            index = args.index('-passgen')
        except:
            print('Password must be provided after -passgen')
            return
        password = args[index + 1]
        key = crypt.str_to_valid_key(password).decode('utf-8')
        print(f'The key for {password} is {key}')
        return

    warn = True
    if '-i' in args:
        warn = False

    out__ = False
    output_file = 'enc.encrypted'
    if '-of' in args:
        try:
            index = args.index('-of')
            output_file = args[index + 1]
            out__ = True
        except:
            print('Output file should be provided after -of')
            return

    path = os.getcwd()

    for i in args:
        if i not in __all__:
            if not i[0] == '-':
                continue
            print('Invalid argument ' + str(i) + ' type -help or ? for help')
            return

    try:
        input_file = args[0]
    except:
        print('Error file name should be the first argument type -help or ? for help')
        return

    # s = os.stat(input_file).st_size

    try:
        filesize = round(os.stat(input_file).st_size / (1024 * 1024), 2)
        filesize_form = f'{filesize}mb'

        if input_file == '/' or input_file == '\\':
            print('Invalid file name')
            return

        if not os.path.exists(input_file):
            print(f'file {input_file} does not exist')
            return

        file = os.path.basename(input_file)

        if os.path.isdir(input_file):
            if not os.listdir(input_file):
                print('Cannot Encrypt empty folders')
                return

            key = crypt.gen_key()

            if '-key' in args:
                try:
                    index = args.index('-key')
                except:
                    print('Key should be provided after -key')
                    return
                key = args[index + 1]
                stat = crypt.check_valid_key(key)
                key = bytes(key, 'utf-8')

                if not stat:
                    print('The key is invalid keys must be 32 long b64 encoded bytes')
                    return

            custom_pass = False
            if '-pass' in args:
                try:
                    index = args.index('-pass')
                    password = args[index + 1]
                    custom_pass = True
                except:
                    print('Password must be provided after -pass argument')
                    return

                key = crypt.str_to_valid_key(password)

            zip_dir(file)
            hide_dir(f'{file}.zip')

            if '-replace' in args:
                if warn:
                    while True:
                        q = input(
                            f'-replace deletes the original file are you sure you would like to proceed y/n add -i to ignore warnings:').lower()

                        if q == 'y':
                            break
                        elif q == 'n':
                            return

                shutil.rmtree(file)

            with open(f'{input_file}.zip', 'rb') as f:
                file_byte_read = f.read()

            os.remove(f'{input_file}.zip')

            output_file = f'{file}_enc.encrypted'

            if os.path.exists(output_file):
                if warn:
                    # print('y')
                    while True:
                        q = input(
                            f'file {output_file} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()

                        if q == 'y':
                            break
                        elif q == 'n':
                            return

            enc_file_byte = crypt.encrypt_bytes(file_byte_read, key)

            enc_input_file = crypt.encrypt(input_file, key)

            with open(output_file, 'wb') as f:
                f.write(enc_file_byte)

            with open(output_file, 'a') as f:
                f.write(f'[{enc_input_file}]!')

            str_key = key.decode('utf-8')
            if custom_pass:
                if INFO:
                    filesize_out = round(
                        os.stat(output_file).st_size / (1024 * 1024), 2)
                    filesize_out_form = f'{filesize_out}mb'
                    diffrence = round(filesize_out-filesize, 2)
                    print(
                        f'Input file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s')
                else:
                    print(
                        f'File encrypted successfully with the this password {password} this is also copied to clipboard the raw key is {str_key}')
                clipboard.copy(password)

            else:
                print(
                    f'File encrypted successfully with the key {str_key} this is also copied to clipboard')
                clipboard.copy(str_key)

            return

        if '-archive' in args:
            key = crypt.gen_key()

            file_data = os.path.splitext(file)
            file_name = file_data[0]

            file_type = file_data[1]

            output_file = f'{file_name}_enc.encrypted'

            if '-key' in args:
                try:
                    index = args.index('-key')
                except:
                    print('Key should be provided after -key')
                    return
                key = args[index + 1]
                stat = crypt.check_valid_key(key)
                key = bytes(key, 'utf-8')

                if not stat:
                    print('The key is invalid keys must be 32 long b64 encoded bytes')
                    return

            custom_pass = False
            if '-pass' in args:
                try:
                    index = args.index('-pass')
                    password = args[index + 1]
                    custom_pass = True
                except:
                    print('Password must be provided after -pass argument')
                    return

                key = crypt.str_to_valid_key(password)

            zip_name = f'{file}zipped.zip'
            if os.path.exists(zip_name):
                if warn:
                    while True:
                        q = input(
                            f'file {zip_name} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()
                        if q == 'y':
                            break
                        elif q == 'n':
                            return
            zipObj = zipfile.ZipFile(zip_name, 'w')
            hide_dir(zip_name)
            zipObj.write(file)
            zipObj.close()

            with open(zip_name, 'rb') as file:
                file_byte_read = file.read()

            os.remove(zip_name)

            if os.path.exists(output_file):
                if warn:
                    # print('y')
                    while True:
                        q = input(
                            f'file {output_file} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()

                        if q == 'y':
                            break
                        elif q == 'n':
                            return
            enc_file_byte = crypt.encrypt_bytes(file_byte_read, key)

            enc_input_file = crypt.encrypt(input_file, key)

            with open(output_file, 'wb') as f:
                f.write(enc_file_byte)

            with open(output_file, 'a') as f:
                f.write(f'[{enc_input_file}]#')

            str_key = key.decode('utf-8')
            if custom_pass:
                if INFO:
                    filesize_out = round(
                        os.stat(output_file).st_size / (1024 * 1024), 2)
                    filesize_out_form = f'{filesize_out}mb'
                    diffrence = round(filesize_out-filesize, 2)

                    print(
                        f'Succsefully encrypted file\nInput file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s\nRaw key: {str_key}\nPassword: {password}')
                else:
                    print(
                        f'File encrypted successfully with the this password {password} this is also copied to clipboard the raw key is {str_key}')
                clipboard.copy(password)

            else:
                if INFO:
                    filesize_out = round(
                        os.stat(output_file).st_size / (1024 * 1024), 2)
                    filesize_out_form = f'{filesize_out}mb'
                    diffrence = round(filesize_out-filesize, 2)

                    print(
                        f'Input file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s')
                else:
                    print(
                        f'File encrypted successfully with the key {str_key} this is also copied to clipboard')
                clipboard.copy(str_key)

            return

        file_data = os.path.splitext(file)
        file_name = file_data[0]

        file_type = file_data[1]

        if not out__:
            output_file = f'{file_name}_enc.encrypted'

        if os.path.exists(output_file):
            if warn:
                # print('y')
                while True:
                    q = input(
                        f'file {output_file} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()

                    if q == 'y':
                        break
                    elif q == 'n':
                        return
        with open(input_file, 'rb') as f:
            file_byte_read = f.read()

        key = crypt.gen_key()

        if '-key' in args:
            try:
                index = args.index('-key')
            except:
                print('Key should be provided after -key')
                return
            key = args[index + 1]
            stat = crypt.check_valid_key(key)
            key = bytes(key, 'utf-8')

            if not stat:
                print('The key is invalid keys must be 32 long b64 encoded bytes')
                return

        if '-pass' in args:
            try:
                index = args.index('-pass')
                password = args[index+1]
            except:
                print('Password must be provided after -pass argument')
                return

            key = crypt.str_to_valid_key(password)

            # print(key, len(key))
            # return

            enc_file_byte = crypt.encrypt_bytes(file_byte_read, key)

            with open(output_file, 'wb') as f:
                f.write(enc_file_byte)

            enc_input_file = crypt.encrypt(input_file, key)

            # enc_input_file = str(enc_file_byte)

            # print(input_file)

            with open(output_file, 'a') as f:
                f.write(f'[{enc_input_file}]')

            str_key = key.decode('utf-8')

            if '-replace' in args:
                if warn:
                    while True:
                        q = input(
                            f'-replace deletes the original file are you sure you would like to proceed y/n add -i to ignore warnings:').lower()

                        if q == 'y':
                            break
                        elif q == 'n':
                            return

                os.remove(input_file)
            # print(str_key)
            if INFO:
                filesize_out = round(
                    os.stat(output_file).st_size / (1024 * 1024), 2)
                filesize_out_form = f'{filesize_out}mb'
                diffrence = round(filesize_out-filesize, 2)

                print(
                    f'Succsefully encrypted file\nInput file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s\nRaw key: {str_key}\nPassword: {password}')
            else:
                print(
                    f'File encrypted successfully with the this password {password} this is also copied to clipboard the raw key is {str_key}')

            clipboard.copy(password)
            return

        enc_file_byte = crypt.encrypt_bytes(file_byte_read, key)

        with open(output_file, 'wb') as f:
            f.write(enc_file_byte)

        enc_input_file = crypt.encrypt(input_file, key)

        with open(output_file, 'a') as f:
            f.write(f'[{enc_input_file}]')

        str_key = key.decode('utf-8')
        # print(str_key)
        if '-replace' in args:
            print('f')
            if warn:
                while True:
                    q = input(
                        f'-replace deletes the original file are you sure you would like to proceed y/n add -i to ignore warnings:').lower()

                    if q == 'y':
                        break
                    elif q == 'n':
                        return

            os.remove(input_file)

        if INFO:
            filesize_out = round(
                os.stat(output_file).st_size / (1024 * 1024), 2)
            filesize_out_form = f'{filesize_out}mb'
            diffrence = round(filesize_out-filesize, 2)

            print(
                f'Input file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s')
        else:
            print(
                f'File encrypted successfully with the key {str_key} this is also copied to clipboard')

        clipboard.copy(str_key)

    except KeyboardInterrupt:
        cl.error('Operation cancelled by user')
