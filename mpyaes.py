import ucryptolib
import uctypes
import uos
import urandom
import ustruct
try:
    MODE_ECB = ucryptolib.MODE_ECB
except AttributeError:
    MODE_ECB = 1
try:
    MODE_CBC = ucryptolib.MODE_CBC
except AttributeError:
    MODE_CBC = 2
try:
    MODE_CTR = ucryptolib.MODE_CTR
except AttributeError:
    MODE_CTR = 6
__MODES = {
    MODE_ECB: 'ECB',
    MODE_CBC: 'CBC',
    MODE_CTR: 'CTR'
}

class PaddingError(Exception):
    pass

class PKCS7:
    
    @staticmethod
    def pad(plaintext: bytearray, block_size: int) -> None:
        # Pads a block. Makes use of bytearray.extend.
        if block_size <= 0:
            raise ValueError('block size must be greater than 0')
        padval = block_size - (len(plaintext) % block_size)
        plaintext.extend(
            bytes(padval for _ in range(padval))
        )
    
    @staticmethod
    def verify(plaintext: bytearray, block_size: int) -> int:
        # Verifies that the padding is correct. Returns size of plaintext without padding.
        if block_size <= 0:
            raise ValueError('block size must be greater than 0')
        if not plaintext:
            raise ValueError('cannot verify padding for empty plaintext')
        pad = plaintext[-1]
        if not (0 < pad <= block_size) or any(plaintext[-1-i] != pad for i in range(pad)):
            raise PaddingError
        return len(plaintext) - pad

def generate_key(x: [bytearray, bytes, int], seed=None) -> [None, bytearray]:
    # Pseudorandomly generates len(x) or x bytes.
    # 32 bits is the maximum amount of bits that can be returned by urandom.getrandbits, as per:
    # https://github.com/micropython/micropython/blob/84fa3312cfa7d2237d4b56952f2cd6e3591210c4/extmod/modurandom.c#L76
    try:
        key_size = len(x)
        buf = x
        return_buf = False
    except TypeError:
        key_size = x
        buf = bytearray(key_size)
        return_buf = True
    if seed is not None:
        urandom.seed(seed)
    q, r = divmod(key_size, 4)  # 32 bits == 4 bytes
    if r:
        if r == 3:
            ustruct.pack_into('>HB', buf, 0, urandom.getrandbits(16), urandom.getrandbits(8))
        else:
            ustruct.pack_into(
                '>H' if r == 2 else '>B', buf, 0, urandom.getrandbits(8*r)
            )
    while q:
        ustruct.pack_into('>I', buf, 4*(q-1) + r, urandom.getrandbits(32))
        q -= 1
    if return_buf:
        return buf

generate_IV = generate_key

class AES:
    def __init__(self, key, mode, IV):
        if mode not in __MODES:
            raise ValueError("unknown mode '{}'".format(mode))
        if IV:
            if len(IV) != 16:
                raise ValueError('only 16-byte IVs are supported')
            self._encryptor = ucryptolib.aes(key, mode, IV)
            self._decryptor = ucryptolib.aes(key, mode, IV)
        else:
            if mode != MODE_ECB:
                raise ValueError('{} mode requires an IV'.format(__MODES[mode]))
            self._encryptor = ucryptolib.aes(key, mode)
            self._decryptor = ucryptolib.aes(key, mode)
        self.block_size = len(key)
        self._mode = mode
        self._filebuf = bytearray(self.block_size)
        self._filebuf_mv = memoryview(self._filebuf)
    
    def __repr__(self):
        return '<AES {}-bit {}>'.format(8*self.block_size, __MODES[self._mode])

    def encrypt(self, plaintext: [bytearray, bytes, str]) -> [None, bytearray]:
        # Encrypts plaintext. If plaintext is a bytearray encryption is done in-place.
        # If not the encrypted bytearray is returned.
        returning = not isinstance(plaintext, bytearray)
        if returning:
            plaintext = bytearray(plaintext)
        PKCS7.pad(plaintext, self.block_size)
        self._encryptor.encrypt(plaintext, plaintext)
        if returning:
            return plaintext

    def decrypt(self, ciphertext: bytearray) -> bytearray:
        # Decrypts ciphertext in-place. Returns a zero-copy bytearray up to where
        # the padding begins.
        self._decryptor.decrypt(ciphertext, ciphertext)
        n = PKCS7.verify(ciphertext, self.block_size)
        return uctypes.bytearray_at(uctypes.addressof(ciphertext), n)

    def encrypt_file(self, f_in_name: str, f_out_name: str):
        block_size = self.block_size
        block_reads = uos.stat(f_in_name)[6] // block_size
        with open(f_in_name, 'rb') as f_in, open(f_out_name, 'wb') as f_out:
            for _ in range(block_reads):
                f_in.readinto(self._filebuf_mv)
                self._encryptor.encrypt(self._filebuf_mv, self._filebuf_mv)
                f_out.write(self._filebuf_mv)
            # Handling the padded block now
            padding = block_size - f_in.readinto(self._filebuf_mv)
            for i in range(padding):
                self._filebuf_mv[-1-i] = padding
            self._encryptor.encrypt(self._filebuf_mv, self._filebuf_mv)
            f_out.write(self._filebuf_mv)
    
    def decrypt_file(self, f_in_name: str, f_out_name: str):
        block_size = self.block_size
        block_reads, not_a_multiple = divmod(uos.stat(f_in_name)[6], block_size)
        if not_a_multiple:
            raise ValueError('file size is not a multiple of block size')
        block_reads -= 1
        with open(f_in_name, 'rb') as f_in, open(f_out_name, 'wb') as f_out:
            for _ in range(block_reads):
                f_in.readinto(self._filebuf_mv)
                self._decryptor.decrypt(self._filebuf_mv, self._filebuf_mv)
                f_out.write(self._filebuf_mv)
            # Handling the padded block now
            f_in.readinto(self._filebuf_mv)
            self._decryptor.decrypt(self._filebuf_mv, self._filebuf_mv)
            n = PKCS7.verify(self._filebuf_mv, block_size)
            f_out.write(self._filebuf_mv[:n])

def new(key, mode, IV=None):
    return AES(key, mode, IV)
