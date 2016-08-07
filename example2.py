#! /usr/bin/python
import pwn

l = pwn.pcapLister(12345)  # the pcap lister.The argument is the port to get pcap
#l.set_sql('explorer', '123456')  # set mysql user os the data will log in databease
l()  # start it
