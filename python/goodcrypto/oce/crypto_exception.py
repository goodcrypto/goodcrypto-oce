'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-06-10

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

class CryptoException(Exception):
    ''' Crypto exception.  '''

    def __init__(self, value=None):
        '''
            Constructor for the CryptoException.

            >>> message = 'oops'
            >>> try:
            ...     raise CryptoException('oops')
            ...     fail()
            ... except CryptoException as message_exception:
            ...     str(message_exception) == message
            True

            >>> try:
            ...     raise CryptoException()
            ... except CryptoException as exception:
            ...     print(exception.value)
            None
        '''

        if value is None:
            super(CryptoException, self).__init__()
        else:
            super(CryptoException, self).__init__(value)

        self.value = value

    def __str__(self):
        '''
            Get the string representation of the exception.

            >>> crypto_exception = CryptoException()
            >>> str(crypto_exception)
            'None'

            >>> crypto_exception = CryptoException('error message')
            >>> isinstance(crypto_exception.__str__(), str)
            True
        '''

        return str(self.value)

