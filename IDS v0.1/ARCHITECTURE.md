# IDS v0.1
## условия составления правил для проверки пакетов

Ключ (Key) |          Ожидаемый формат значения |           Пример в rules.txt
	
sid |                 число без кавычек |                   sid=1, sid=2 и т. п.

msg |                 Строка (желательно в кавычках) |      msg="SYN scan detected"

src_mac |             MAC-адрес (6 пар hex через :) |       src_mac=74:27:ea:58:42:13
	
dst_mac |            MAC-адрес (6 пар hex через :) |      dst_mac=ff:ff:ff:ff:ff:ff
	
ethertype |          Hex-число |                          ethertype=0x0800
	
src_ip |             IPv4 или CIDR-подсеть |              src_ip=192.168.1.0/24 или 10.0.0.5
	
dst_ip |             IPv4 или CIDR-подсеть |              dst_ip=172.16.0.0/16
	
proto |              Строка (название протокола) |        proto=tcp или proto=UDP
	
ttl |                Десятичное число |                   ttl=64

ihl_min |            Десятичное число |                   ihl_min=5
	
ihl_max |            Десятичное число |                   ihl_max=15
	
sport |              Десятичное число (0-65535) |         sport=12345
	
dport |              Десятичное число (0-65535) |            dport=80
	
flags |        Строка символов (разледитель ',', ' ') |   flags=S,A или flags=S A

length_datagram |    Десятичное число (> 0) |             length_datagram=1500
	
type |               Десятичное число |                   type=8
	
code |               Десятичное число |                   code=0
	
ICMP_size |          Десятичное число (> 0) |             ICMP_size=64
	
