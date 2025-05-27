class User:
    
    __slots__ = ('username', 'password', 'mode', 'addr', 'conn', 'publicKey', 'recipient')
    def __init__(self, username, password, mode, addr, conn, publicKey):

        self.username = username
        self.password = password
        self.mode = mode
        self.addr = addr
        self.conn = conn
        self.publicKey = publicKey
        self.recipient = None

    def print_function(self):       
        return [].add(self.password, self.mode)
