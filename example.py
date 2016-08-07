#! /usr/bin/python
import pwn


def getFlag():
    '''
    The function to get call for get flag.You can make a different flag for different listen
    '''
    return 'a flag'


a = pwn.daemon(0)  # A demon class,The argument is the second of time out, 0 is no timeout

a.set_listen(9999)  # The port you want to listen
a.set_process('/home/explorer/ctf/pwn3/pwn3', cwd='/home/pwn')  # first argument is the binary,
# make sure other has permission of execute for it
a.set_sql('explorer', '123456')  # The name and password of mysql. Default it will log data in database pwnlog.
# But you can easy change it.And dot't worry of table.I will create it
a.open_permission()
a(getFlag)  # start it
