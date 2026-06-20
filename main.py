import hashlib
import gi
gi.require_version('Gdk', '3.0')
from ulauncher.api.client.Extension import Extension
from ulauncher.api.client.EventListener import EventListener
from ulauncher.api.shared.event import KeywordQueryEvent
from ulauncher.api.shared.item.ExtensionResultItem import ExtensionResultItem
from ulauncher.api.shared.action.RenderResultListAction import RenderResultListAction
from ulauncher.api.shared.action.CopyToClipboardAction import CopyToClipboardAction

def md4(data):
    # Prefer OpenSSL's MD4 when available, fall back to a pure-Python
    # implementation (OpenSSL 3 drops MD4 from the default provider).
    try:
        digest = hashlib.new('md4')
        digest.update(data)
        return digest.digest()
    except (ValueError, TypeError):
        return _md4_pure(data)

def _md4_pure(data):
    # RFC 1320 MD4
    import struct

    def lrot(x, n):
        x &= 0xffffffff
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    msg = bytearray(data)
    length = (8 * len(data)) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', length)

    for off in range(0, len(msg), 64):
        x = list(struct.unpack('<16I', msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d

        def f(x, y, z): return (x & y) | (~x & z)
        def g(x, y, z): return (x & y) | (x & z) | (y & z)
        def h(x, y, z): return x ^ y ^ z

        for i in range(4):
            k = i * 4
            a = lrot(a + f(b, c, d) + x[k], 3)
            d = lrot(d + f(a, b, c) + x[k + 1], 7)
            c = lrot(c + f(d, a, b) + x[k + 2], 11)
            b = lrot(b + f(c, d, a) + x[k + 3], 19)
        for i in range(4):
            a = lrot(a + g(b, c, d) + x[i] + 0x5a827999, 3)
            d = lrot(d + g(a, b, c) + x[i + 4] + 0x5a827999, 5)
            c = lrot(c + g(d, a, b) + x[i + 8] + 0x5a827999, 9)
            b = lrot(b + g(c, d, a) + x[i + 12] + 0x5a827999, 13)
        for i in [0, 2, 1, 3]:
            a = lrot(a + h(b, c, d) + x[i] + 0x6ed9eba1, 3)
            d = lrot(d + h(a, b, c) + x[i + 8] + 0x6ed9eba1, 9)
            c = lrot(c + h(d, a, b) + x[i + 4] + 0x6ed9eba1, 11)
            b = lrot(b + h(c, d, a) + x[i + 12] + 0x6ed9eba1, 15)

        a = (a + aa) & 0xffffffff
        b = (b + bb) & 0xffffffff
        c = (c + cc) & 0xffffffff
        d = (d + dd) & 0xffffffff

    return struct.pack('<4I', a, b, c, d)

class Hash(Extension):
    def __init__(self):
        super(Hash, self).__init__()
        self.subscribe(KeywordQueryEvent, KeywordQueryEventListener())

class KeywordQueryEventListener(EventListener):
    def on_event(self, event, extension):
        items = []
        text = event.get_argument() or ''
        keyword = event.get_keyword()

        # Find the keyword id using the keyword (since the keyword can be changed by users)
        for kwId, kw in extension.preferences.items():
            if kw == keyword:
                keywordId = kwId

        if keywordId == 'ntlm':
            nt_hash = md4(text.encode('utf-16-le')).hex()
            items.append(ExtensionResultItem(icon='icon.svg', name=nt_hash, description='NTLM (NT hash)', on_enter=CopyToClipboardAction(nt_hash), highlightable=False))
            return RenderResultListAction(items)

        argument = text.encode('utf-8')

        # Show the algorithm specified as keyword, or all if the keyword was "hash"
        algos = hashlib.algorithms_guaranteed if keywordId == 'hash' else [keywordId]

        for algo in algos:
            try:
                seed = hashlib.new(algo)
                seed.update(argument)
                hash = seed.hexdigest()
                items.append(ExtensionResultItem(icon='icon.svg', name=hash, description=algo, on_enter=CopyToClipboardAction(hash), highlightable=False))
            except:
                pass

        return RenderResultListAction(items)

if __name__ == '__main__':
    Hash().run()
