#!/usr/bin/python3

import hashlib
import random
import socket
from threading import Thread

class Kademlia:
    def __init__(self, k, id_len=32):
        self.k = k
        self.id_len = id_len


def do_hash(s):
    m = hashlib.sha1()
    m.update(s.encode("utf-8"))
    return int.from_bytes(m.digest(), byteorder="big")

def generate_host_id(kad):
    return random.getrandbits(kad.id_len)

class RemoteNode:
    def __init__(self, kad, host_id, sock, addr):
        self.kad = kad
        self.host_id = host_id
        self.sock = sock
        self.addr = addr
        print("connected to", self.addr, hex(self.host_id))

class LocalNode:
    def __init__(self, kad, host_id=None):
        self.kad = kad
        if host_id is not None:
            self.host_id = host_id
        else:
            self.host_id = generate_host_id(self.kad)
        self.buckets = [[] for i in range(self.kad.id_len)]
        self.buckets[self.kad.id_len-1].append(self)
        self.store = {}
        self.addr = ("0.0.0.0", random.randint(0x8000, 0x8fff))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        print(self.addr)
        print(hex(self.host_id))
        print("----")

    def get_bucket_id_for_node_id(self, node_id):
        for i in range(self.kad.id_len):
            b1 = self.host_id & (1 << (self.kad.id_len-1-i))
            b2 = node_id & (1 << (self.kad.id_len-1-i))
            if b1 != b2:
                return i
        return self.kad.id_len-1

    def get_bucket_id_for_node(self, node):
        return self.get_bucket_id_for_node_id(node.host_id)

    def get_bucket_for_node_id(self, node_id):
        return self.buckets[self.get_bucket_id_for_node_id(node_id)]

    def get_bucket_for_node(self, node):
        return self.get_bucket_for_node_id(node.host_id)

    def insert_node(self, node):
        b = self.get_bucket_for_node(node)
        if len(b) < self.kad.k:
            b.append(node)
        else:
            # TODO if there are old nodes, replace one of them
            pass

    def find_closest(self, key):
        return self.get_bucket_for_node_id(key).copy()

    def put(self, key, value):
        print("put", key, "=", value)
        l = self.find_closest(key)
        if l:
            for node in l:
                print("-->", node)
                node.put(key, value)
        else:
            print("storing locally")
            if key not in self.store:
                self.store[key] = []
            self.store[key].append(value)

    def get(self, key):
        if key in self.store:
            return self.store[key]
        else:
            for node in self.find_closest(key):
                v = node.get(key)
                if (v):
                    return v
            return None

    def listen_loop(self):
        while self.is_running:
            data, addr = self.sock.recvfrom(1024)
            print("received",data,"from",addr)
            s = data.decode("utf-8")
            cmd = s.split()
            if len(cmd) < 1:
                continue
            if cmd[0] == "wesh":
                self.sock.sendto(("host_id "+str(self.host_id)).encode("utf-8"),
                        addr)
                self.insert_node(RemoteNode(self.kad, int(cmd[1]),
                    self.sock, addr))
            elif cmd[0] == "host_id":
                self.insert_node(RemoteNode(self.kad, int(cmd[1]),
                    self.sock, addr))

    def run(self):
        self.is_running = True
        self.listen_thread = Thread(target=self.listen_loop)
        self.listen_thread.start()
        while self.is_running:
            try:
                i = input()
            except EOFError:
                i = "exit"
            cmd = i.split()
            if len(cmd) < 1:
                continue
            if cmd[0] == "exit":
                self.is_running = False
            elif cmd[0] == "connect":
                self.sock.sendto(("wesh "+str(self.host_id)).encode("utf-8"),
                        (cmd[1], int(cmd[2])))
            elif cmd[0] == "route":
                for i, b in enumerate(self.buckets):
                    print(i, b)
        self.sock.sendto(b"", self.addr)
        self.listen_thread.join()

kad = Kademlia(k=8)
l1 = LocalNode(kad)
l1.run()
