import zono.cli as cli
import ddos_module as ddos_attacks
import scanners
import enc.encrypt
import enc.decrypt


app = cli.Application()


ddos_module = app.module(name='DDOS', description='Group of ddos commands')
info_module = app.module(
    name='info', description='Group of network info commands')
enc_module = app.module(
    name='Cryptography', description='Group of commands related to cryptography')


@ddos_module.command(description='Runs a udpflood attack')
def udp(ctx):
    ddos_attacks.ddos.udp_flooder(ctx)


@info_module.command(description='Scans network')
def lan_scanner(ctx):
    scanners.lan_scan(ctx)


@info_module.command(description='Gets mac of a ip')
def macgetter(ctx):
    scanners.get_mac(ctx)


@info_module.command(description='Lookup an ips info')
def ipinfo(ctx):
    scanners.ipinfo(ctx)


@enc_module.command(description='Encrypts a file')
def encryptfile(ctx):
    enc.encrypt.main(ctx)


@enc_module.command(description='Decrypts a file')
def decryptfile(ctx):
    enc.decrypt.main(ctx)



app.run()
