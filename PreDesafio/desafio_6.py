from utils import read_file, convert_hex_to_bin, convert_bin_to_hex, convert_bin_to_ascii, decrypt_by_single_byte, default_evaluate, partion, xor, start, finish
import base64

def main():
    start("Desafio 6")

    hex_text = base64.b64decode("".join(read_file("6.txt"))).hex()
    scores = []
    keysize = []
    for ks in range(2, 41):      
        a = partion(hex_text, 2*ks)
        bin_text = [convert_hex_to_bin(h) for h in a]
        s = []
        for i in range(0, 4):
            s.append(xor(bin_text[i], bin_text[i + 1]).count("1"))
        s = sum(s)/ks
        keysize.append(ks)
        scores.append(s)

    best_keys = []
    for i in range(0, 4):
        i = scores.index(min(scores))
        best_keys.append(keysize[i])
        keysize.pop(i)
        scores.pop(i)

    texts = {}
    for ks in best_keys:
        bin_text = partion(convert_hex_to_bin(hex_text), 8*ks)
        blocks = [[] for _ in range(0, ks)]
        for x in bin_text:
            for i, y in enumerate(partion(x, 8)):
                blocks[i%ks].append(y)

        hex_texts = []
        for block in blocks:
            hex_texts.append(convert_bin_to_hex("".join(block)))

        chars = []
        key = []
        for h in hex_texts:
            t, k, s = decrypt_by_single_byte(h)
            chars.append(t)
            key.append(k)

        text = ""
        for i, c in enumerate(chars[0]):
            for h in chars:
                if i < len(h):
                    text += h[i]
        key = "".join([convert_bin_to_ascii(k) for k in key])

        texts[key] = text

    best_score = -1
    best_text = -1
    for k in texts.keys():
        score = default_evaluate(texts[k])
        if score > best_score:
            best_text = k
            best_score = score
    
    print(f"Key: {best_text}\n\n{texts[best_text]}")

    finish()

main()
