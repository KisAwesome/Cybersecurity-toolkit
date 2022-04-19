import ddos as udpflooder


class ddos:
    @staticmethod
    def udp_flooder(ctx):
        print(ctx.args)
        udpflooder.main(ctx)
