# coding:utf-8
import dpkt
import time


# 该函数用于IP地址十六进制到点分十进制的转化
def addr2str(addrobj):
    if len(addrobj) != 4:
        return "addr error!"
    else:
        return str(addrobj[0]) + "." + str(addrobj[1]) + "." + str(addrobj[2]) + "." + str(addrobj[3])

# 判断协议类型，还有待完善
def TCPorUDP(obj):
    if obj == 0x01:
        return "ICMP"

    elif obj == 0x02:
        return "IGMP"

    elif obj == 0x06:
        return "TCP"

    elif obj == 0x08:
        return "EGP"

    elif obj == 0x09:
        return "IGP"

    elif obj == 0x11:
        return "UDP"

    elif obj == 0x29:  # 41
        return "IPv6"

    elif obj == 0x59:  # 89
        return "OSPF"

    else:
        return "error"


def main():
    fw = open("result.txt", "w")  # result.txt是解析之后的文件
    f = open("demo.pcap", "rb")  #  demo.pcap是抓包生成的文件

    pcap = dpkt.pcap.Reader(f)
    i = 0

    for ts, buf in pcap:

        pktheader = buf[14:34]
        trans_type = 'c'  # 有时会报错,所以这里有一个字符替换默认
        try:
            trans_type = pktheader[9]
        except Exception as es:
            pass

        srcip = pktheader[12:16]
        dstip = pktheader[16:20]

        fw.writelines("No：" + str(i + 1))
        fw.writelines("\t源IP: " + addr2str(srcip) + "\t目标IP:" + addr2str(dstip))
        fw.writelines("\t协议类型:" + TCPorUDP(trans_type))
        # 目前传输层协议类型只解析出了UDP和TCP
        if trans_type == 0x11:  # UDP

            udpheader = buf[34:42]

            srcport = udpheader[0:2]

            dstport = udpheader[2:4]

            fw.writelines("\t源端口:" + str(srcport[1] + srcport[0] * 16 * 16) + "\t目标端口:" + str(
                dstport[1] + dstport[0] * 16 * 16))
        elif trans_type == 0x06:  # TCP

            tcpheader = buf[34:54]

            srcport = tcpheader[0:2]

            dstport = tcpheader[2:4]

            fw.writelines("\t源端口:" + str(srcport[1] + srcport[0] * 16 * 16) + "\t目标端口:" + str(
                dstport[1] + dstport[0] * 16 * 16))
        else:
            fw.writelines("\t无法确定协议类型")
        i = i + 1
        fw.writelines("\t总长度：" + str(pktheader[3] + pktheader[2] * 16 * 16) +
                      "\tTTL：" + str(pktheader[8]) + "\tMF：" + str(pktheader[6] // 128) +
                      "\tDF：" + str((pktheader[6] // 64) - (pktheader[6] // 128)) +
                      "\toffset：" + str(pktheader[7] + (pktheader[6] % 32) * 16 * 16) +
                      "\t首部校验和：" + str(pktheader[11] + pktheader[10] * 16 * 16))

        # 转换成localtime
        time_local = time.localtime(ts)
        # 转换成新的时间格式(2020-11-11 11:1111)
        datetimes = time.strftime("%Y-%m-%d %H:%M:%S", time_local)

        fw.writelines("\t时间:" + str(datetimes) + "\n")
    f.close()
    print("解析协议个数:", i)


if __name__ == "__main__":
    main()
    print('end')
