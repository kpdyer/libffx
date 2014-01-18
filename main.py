import md5
import math
import string
import random
import unittest

import Crypto.Util.number
import gmpy

CHARS = ['0','1']#,'1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i']
RADIX = len(CHARS)
ZERO_BIT = '0'
bits = 8

class Bottom(Exception):
    pass

class UnknownTypeException(Exception):
    pass

class FFXInteger(object):
    
    def __init__(self, x, radix=RADIX, blocksize=None):
        if type(x) in [int,long]:
            self._x = gmpy.digits(x, radix)
        elif type(x) in [str]:
            self._x = x
        elif type(x) in [FFXInteger]:
            self._x = x.to_str()
        else:
            raise UnknownTypeException(type(x))
            
        self._len = len(self._x)
        self._radix = radix
        self._blocksize = blocksize
        
    def __add__(self,other):
        assert other._radix == self._radix, (other._radix, self._radix)
        assert other._blocksize == self._blocksize, (other._blocksize, self._blocksize)
        
        other = FFXInteger(other, self._radix, self._blocksize)
        
        retval = self.to_int()
        retval += other.to_int()
        retval = gmpy.digits(retval, self._radix)
        
        if self._blocksize!=None:
            retval = string.rjust(retval, self._blocksize, '0')
        
        return FFXInteger(retval, self._radix, self._blocksize)
    
    def __eq__(self, other):
        #print [type(other), other]the weepies
        if type(other) == FFXInteger:
            retval = self.to_int() == other.to_int()
        elif type(other) in [str]:
            retval = self._x == other
        else:
            raise UnknownTypeException()
        return retval
    
    def __len__(self):
        return len(self._x)
    
    def __getitem__(self, i):
        #print [self._x, i]
        return FFXInteger(self._x[i], self._radix, 1)
    
    def __getslice__(self, i, j):
        #print ['i','j',i,j]
        return FFXInteger(self._x[i:j], self._radix, len(self._x[i:j]))
    
    def __repr__(self):
        return self._x
    
    def __str__(self):
        return self._x
    
    def to_int(self):
        return int(self._x, self._radix)
    
    def to_bytes(self):
        _cur_len = len(self._x)
        num_bytes = int(_cur_len/8.0)
        retval = long_to_bytes(self.to_int(),num_bytes)
        return retval
    
    def to_str(self):
        retval = str(self._x)
        if self._blocksize is not None:
            retval = string.rjust(self._x, self._blocksize, ZERO_BIT)
        return retval
    

def bytes_to_long(X):
    return Crypto.Util.number.bytes_to_long(X)

def long_to_bytes(n, blocksize=0):
    return Crypto.Util.number.long_to_bytes(n, blocksize)



############

def CBC_MAC(K, X):
    """TODO"""
    #assert len(X)%16 == 0, len(X)%16
    #print ['K','X', K, X]
    m = md5.new()
    m.update(X)
    return m.digest()

def isEven(n):
    return ((n%2)==0)


def xor(X, Y, chars, plus=True):
    #print ['xor', type(X), type(Y), type(X[0]), X, Y]
    #assert len(X) == len(Y)
    assert X._radix == Y._radix, (X._radix, Y._radix)
    assert X._blocksize == Y._blocksize, (X._blocksize, Y._blocksize)
    
    if len(X)>len(Y):
        X_str = str(X)
        Y_str = string.rjust(Y.to_str(), len(X), ZERO_BIT)
    elif len(Y)>len(X):
        X_str = string.rjust(X.to_str(), len(Y), ZERO_BIT)
        Y_str = str(Y)
    else:
        X_str = str(X)
        Y_str = str(Y)
    retval = ''
    
    #print ['X','Y',X_str,Y_str,retval]
    #print ['X','Y',type(X_str),type(Y_str)]
    for i in range(len(X_str)):
        assert X_str[i] in chars
        assert Y_str[i] in chars
        retchar = chars.index(X_str[i])
        if plus:
            retchar += chars.index(Y_str[i])
        else:
            retchar -= chars.index(Y_str[i])
        retchar %= len(chars)
        retchar = chars[retchar]
        retval += retchar
    
    return FFXInteger(retval, X._radix, X._blocksize)

def add(X,Y,chars=CHARS):
    return xor(X,Y,chars,True)

def sub(X,Y,chars=CHARS):
    return xor(X,Y,chars,False)


def rnds(n):
    """TODO"""
    if n >= 8 and n <= 9:
        retval = 36
    if n >= 10 and n <= 13:
        retval = 30
    if n >= 14 and n <= 19:
        retval = 24
    if n >= 20 and n <= 31:
        retval = 18
    if n >= 32 and n <= 128:
        retval = 12
    return retval
        
def split(n):
    """TODO"""
    return int(math.floor((n*1.0)/2))

def F(K,n,T,i,B):
    #print ['F', K,n,T,i,B]
    
    vers = 1
    method = 2
    addition = 0
    radix = RADIX
    
    P  = long_to_bytes(vers, 2)
    P += long_to_bytes(method, 1)
    P += long_to_bytes(addition, 1)
    P += long_to_bytes(radix, 1)
    P += long_to_bytes(n, 1)
    P += long_to_bytes(split(n), 1)
    P += long_to_bytes(rnds(n), 1)
    P += long_to_bytes(len(T), 8)
    
    assert len(P) == 16
    
    #print ['T',T]
    Q  = T.to_str()
    Q += FFXInteger( ZERO_BIT, radix=RADIX , blocksize= (((-1*len(T))-1) % 16)*8 ).to_str()
    #print [i]
    Q += FFXInteger(i,radix=RADIX,blocksize=8).to_str()
    #print ['FFXInteger(i).to_str()',FFXInteger(i).to_str()]
    Q += (ZERO_BIT * 8 * (64-len(B)))
    #print ['B',B]
    Q += B.to_str()
    
    #Q =
    #print [len(P), len(Q), P, Q]
    Q = FFXInteger(Q, radix=RADIX)
    #print [len(Q),len(Q)]
    Q = Q.to_bytes()
    
    #print [len(T), (((-1*len(T))-9) % 16), 1, 64-len(B), len(B)]
    #assert len(P) == 16
    
    #print [len(P), len(Q), P, Q]
    Y = CBC_MAC(K, P + Q)
    
    #print ['n',n]
    if isEven(i):
        m = split(n)
    else:
        #m = n - split(n)
        m = split(n)
    #print ['m',m]
    
    Y = bin(int(Y.encode('hex'),base=16))[2:]
    #print ['Y', m, Y[-m:]]
    #print ['B',B[-m:]]
    return FFXInteger(Y[-m:],radix=RADIX,blocksize=m)

def ffx_encrypt(K,T,X):
    """assertions"""
    retval = ''
    n = len(X)
    l = split(n)
    r = rnds(n)
    A = X[:l]
    B = X[l:]
    for i in range(r):
        #print [type(A),type(F(K,n,T,i,B))]
        #print ['A,F',A, F(K,n,T,i,B) ]
        C = add( A, F(K,n,T,i,B) )
        #print [i,'B','C',B,C]
        A = B
        B = C
        #X = FFXInteger(str(B) + str(C),radix=RADIX,blocksize=len(B)+len(C))
    retval = FFXInteger(str(A) + str(B),radix=RADIX,blocksize=len(A)+len(B))        
    return retval

def ffx_decrypt(K,T,Y):
    """assertions"""
    retval = ''
    
    n = len(Y)
    l = split(n)
    r = rnds(n)
    
    A = Y[:l]
    B = Y[l:]
    for i in range(r-1,-1,-1):
        C = B
        B = A
        #print [i, 'Y,C,n,n-l,F',Y, C, n, n-l,F(K,n,T,i,B)]
        A = sub(C, F(K,n,T,i,B))
        
    retval = FFXInteger(str(A) + str(B),radix=RADIX,blocksize=len(A)+len(B))
        
    return retval

def test():
    X = FFXInteger('001')
    Y = FFXInteger('001')
    assert X + Y == FFXInteger('010'), X+Y
    
    X = FFXInteger('1001')
    Y = FFXInteger('0001')
    assert X[1:] + Y[1:] == FFXInteger('010'), X[1:] + Y[1:]
    
    X = FFXInteger('100')
    Y = FFXInteger('100')
    assert X + Y == FFXInteger('1000'), X+Y
    
    assert add(X, Y) == FFXInteger('000'), add(X,Y)
    assert sub(X, Y) == FFXInteger('000'), sub(X,Y)

def random_int(length):
    retval = ''
    for i in range(length):
        retval += random.choice(CHARS)
    return retval


def main():
    for i in range(2**16):
        K = random_int(bits)
        T = random_int(bits)
        M1 = random_int(bits)
        
        K = string.rjust(K, bits, '0')
        T = string.rjust(T, bits, '0')
        M1 = string.rjust(M1, bits, '0')
        
        K  = FFXInteger(K, radix=RADIX, blocksize=bits)
        T  = FFXInteger(T, radix=RADIX, blocksize=bits)
        M1 = FFXInteger(M1, radix=RADIX, blocksize=bits)
        C = ffx_encrypt(K, T, M1)
        M2 = ffx_decrypt(K, T, C)
        
        print ['K,T,M1,C,M2', K, T, M1,C,M2]
        
        assert M1 == M2
    
if __name__ == "__main__":
    #test()
    main()