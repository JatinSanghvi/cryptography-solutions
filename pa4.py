"""
In this project you will experiment with a padding oracle attack against a toy web site hosted at
crypto-class.appspot.com. Padding oracle vulnerabilities affect a wide variety of products, including secure tokens.
This project will show how they can be exploited. We discussed CBC padding oracle attacks in Lecture 7.6, but if you
want to read more about them, please see Vaudenay's paper.

Now to business. Suppose an attacker wishes to steal secret information from our target web site
crypto-class.appspot.com. The attacker suspects that the web site embeds encrypted customer data in URL parameters such
as this:

http://crypto-class.appspot.com/po?er=f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad
3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4

That is, when customer Alice interacts with the site, the site embeds a URL like this in web pages it sends to Alice.
The attacker intercepts the URL listed above and guesses that the ciphertext following the "po?er=" is a hex encoded AES
CBC encryption with a random IV of some secret data about Alice's session.

After some experimentation the attacker discovers that the web site is vulnerable to a CBC padding oracle attack. In
particular, when a decrypted CBC ciphertext ends in an invalid pad the web server returns a 403 error code (forbidden
request). When the CBC padding is valid, but the message is malformed, the web server returns a 404 error code (URL not
found).

Armed with this information your goal is to decrypt the ciphertext listed above. To do so you can send arbitrary HTTP
requests to the web site of the form

http://crypto-class.appspot.com/po?er="your ciphertext here"

and observe the resulting error code. The padding oracle will let you decrypt the given ciphertext one byte at a time.
To decrypt a single byte you will need to send up to 256 HTTP requests to the site. Keep in mind that the first
ciphertext block is the random IV. The decrypted message is ASCII encoded.

To get you started here is a short Python script that sends a ciphertext supplied on the command line to the site and
prints the resulting error code. You can extend this script (or write one from scratch) to implement the padding oracle
attack. Once you decrypt the given ciphertext, please enter the decrypted message in the box below.

This project shows that when using encryption you must prevent padding oracle attacks by either using encrypt-then-MAC
as in EAX or GCM, or if you must use MAC-then-encrypt then ensure that the site treats padding errors the same way it
treats MAC errors.
"""

import Queue
import threading
import urllib2

block_size = 32
paddings = ['00000000000000000000000000000001',
            '00000000000000000000000000000202',
            '00000000000000000000000000030303',
            '00000000000000000000000004040404',
            '00000000000000000000000505050505',
            '00000000000000000000060606060606',
            '00000000000000000007070707070707',
            '00000000000000000808080808080808',
            '00000000000000090909090909090909',
            '0000000000000A0A0A0A0A0A0A0A0A0A',
            '00000000000B0B0B0B0B0B0B0B0B0B0B',
            '000000000C0C0C0C0C0C0C0C0C0C0C0C',
            '0000000D0D0D0D0D0D0D0D0D0D0D0D0D',
            '00000E0E0E0E0E0E0E0E0E0E0E0E0E0E',
            '000F0F0F0F0F0F0F0F0F0F0F0F0F0F0F',
            '10101010101010101010101010101010']


def xor_block(hex_num1, hex_num2, hex_num3):
    return format(int(hex_num1, 16) ^ int(hex_num2, 16) ^ int(hex_num3, 16), '032x')


def replace_block(block, hex_byte, byte_position):
    return block[:(block_size - byte_position * 2 - 2)] + hex_byte + block[(block_size - byte_position * 2):block_size]


class Requestor(threading.Thread):
    def __init__(self, result_val, url, result_queue):
        threading.Thread.__init__(self)
        self.result_val = result_val
        self.url = url
        self.result_queue = result_queue

    def run(self):
        try:
            urllib2.urlopen(self.url)
        except urllib2.HTTPError, e:
            if e.code != 404:
                return
        self.result_queue.put(self.result_val)


def decrypt_byte(ciphertext_block, message_block, byte_position):
    target = 'http://crypto-class.appspot.com/po?er='
    threads = []
    result_queue = Queue.Queue()
    for guess in range(128):
        query = xor_block(ciphertext_block[:32], replace_block(message_block, format(guess, '02x'), byte_position),
                          paddings[byte_position]) + ciphertext_block[32:]
        threads.append(Requestor(guess, target + query, result_queue))

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # In rare situations, two guesses can result in HTTP error 404. For example, the message block ending with 02?? will
    # result in 404 for both values 01 and 02 of the last bit.
    result = 0
    while not result_queue.empty():
        result = max(result, result_queue.get())
    return format(result, '02x')


def decrypt_block(ciphertext_block):
    message_block = '0' * block_size
    for byte_position in range(16):
        hex_byte = decrypt_byte(ciphertext_block, message_block, byte_position)
        message_block = replace_block(message_block, hex_byte, byte_position)
    return message_block


def decrypt_message(ciphertext):
    message_blocks = len(ciphertext) / block_size - 1
    message = ''
    for block_num in range(message_blocks):
        message += decrypt_block(ciphertext[block_num * block_size:(block_num + 2) * block_size])
    return message


def main():
    ciphertext = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd' \
                 '4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'

    print decrypt_message(ciphertext).decode('hex')


if __name__ == "__main__":
    main()
