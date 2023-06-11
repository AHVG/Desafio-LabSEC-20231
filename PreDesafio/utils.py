def start(msg):
    print("="*120)
    print(f"{msg:^120}")
    print("="*120)
    print()


def finish():
    print()
    print("="*120)
    print("="*120)


def read_file(file_name):
    with open(file_name, "r") as file:
        lines = file.readlines()

    new_lines = []
    for line in lines:
        new_lines.append(line.replace("\n", ""))

    return new_lines[:]


# Particiona uma string em grupos de n
def partion(s, n):
    new_s = ""
    for i in range(0, len(s)):
        new_s += s[i]
        if (i + 1) % n == 0:
            new_s += " "
    return new_s.split()


def convert_bin_to_hex(bin_code):
    tab_bin_to_hex = {"0000": "0", "0001": "1", "0010": "2", "0011": "3",
                      "0100": "4", "0101": "5", "0110": "6", "0111": "7",
                      "1000": "8", "1001": "9", "1010": "a", "1011": "b",
                      "1100": "c", "1101": "d", "1110": "e", "1111": "f"}

    hex_code = ""
    for i in range(0, len(bin_code), 4):
        hex_code += tab_bin_to_hex[bin_code[i:i+4]]
    return hex_code


def convert_hex_to_bin(hex_code):
    tab_hex_to_bin = {"0": "0000", "1": "0001", "2": "0010", "3": "0011",
                      "4": "0100", "5": "0101", "6": "0110", "7": "0111",
                      "8": "1000", "9": "1001", "a": "1010", "b": "1011",
                      "c": "1100", "d": "1101", "e": "1110", "f": "1111"}

    bin_code = ""
    for c in hex_code:
        bin_code += tab_hex_to_bin[c]
    return bin_code


def convert_bin_to_dec(bin_code):
    dec = 0
    for i, c in enumerate(bin_code[::-1]):
        dec += int(c)*2**i
    return dec


def convert_dec_to_bin(dec_code, digits):
    bin = ""
    if dec_code <= 0:
        return "0" * digits
    while dec_code != 0:
        q = dec_code // 2
        r = dec_code % 2
        dec_code = q
        bin += str(r)

    bin = bin[::-1]

    if digits < len(bin):
        return bin[:digits]
    return ((digits - len(bin)) * "0") + bin


def convert_bin_to_base64(bin_code):

    tab_char_to_64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    base64 = ""

    bin_code = partion(bin_code, 4)
    r = len(bin_code) % 3
    [bin_code.append("00000000") for i in range(r)]

    bin_code = partion("".join(bin_code), 6)

    for p in bin_code:
        if len(p) == 6:
            base64 += tab_char_to_64[convert_bin_to_dec(p)]
    base64 = base64[:len(base64) - r] + r * "="
    return base64


def convert_hex_to_base64(hex_code):
    return convert_bin_to_base64(convert_hex_to_bin(hex_code))


def convert_ascii_to_bin(string):
    binary = ""
    for c in string:
        binary += convert_dec_to_bin(ord(c), 8)
    return binary


def convert_bin_to_ascii(bin):
    text = ""
    bin = partion(bin, 8)
    for b in bin:
        text += chr(convert_bin_to_dec(b))
    return text


def convert_hex_to_ascii(hex):
    return convert_bin_to_ascii(convert_hex_to_bin(hex))


def decode(msg, key):
    return convert_bin_to_hex(xor(convert_hex_to_bin(msg), convert_hex_to_bin(key)))


# Gera keys em binário de tamanho igual a "digits"
def generate_keys(digits):
    return [convert_dec_to_bin(i, digits) for i in range(0, 2**digits)]


def xor(bin1, bin2):
    r = ""
    for i, _ in enumerate(bin1):
        r += "0" if bin1[i] == bin2[i] else "1"
    return r


def xor_hex(hex1, hex2):
    return convert_bin_to_hex(xor(convert_hex_to_bin(hex1), convert_hex_to_bin(hex2)))


# Quanto maior o valor melhor


def default_evaluate(text):

    points_table = {"a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 13.0,
                    "f": 2.2, "g": 2.0, "h": 6.1, "i": 7.0, "j": 0.15,
                    "k": 0.77, "l": 4, "m": 2.4, "n": 6.7, "o": 7.5,
                    "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1,
                    "u": 2.8, "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0,
                    "z": 0.074, " ": 15.0}

    score = 0
    for c in text.lower():
        points = points_table.get(c)
        if points is None:
            continue
        score += points
    return score

# Quanto menor o valor melhor


def evaluate_by_aproximation(text):

    points_table = {"a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 13.0,
                    "f": 2.2, "g": 2.0, "h": 6.1, "i": 7.0, "j": 0.15,
                    "k": 0.77, "l": 4, "m": 2.4, "n": 6.7, "o": 7.5,
                    "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1,
                    "u": 2.8, "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0,
                    "z": 0.074, " ": 13.0}

    points = points_table.copy()
    for k in points.keys():
        points[k] = 0

    letters = 0
    for c in text.lower():
        letters += 1
        if points_table.get(c) is None:
            continue
        points[c] += 1

    if letters != 0:
        for k in points.keys():
            points[k] = 100 * points[k] / letters

    for k in points_table.keys():
        points[k] = (points[k] - points_table[k]
                     ) if points[k] > points_table[k] else (points_table[k] - points[k])

    score = 0
    for k in points.keys():
        score += points[k]

    return score


def decrypt_by_single_byte(hex):
    keys = generate_keys(8)
    encrypted_binary_text = partion(convert_hex_to_bin(hex), 8)

    texts = []
    scores = []
    for k in keys:
        decrypted_text = convert_bin_to_ascii(
            "".join([xor(c, k) for c in encrypted_binary_text]))
        texts.append(decrypted_text)
        scores.append(default_evaluate(decrypted_text))

    best_score = sorted(scores[:])[-1]
    best_score_index = scores.index(best_score)

    return texts[best_score_index], keys[best_score_index], best_score


def repeting_key_xor(text, key):

    bin_key = partion(convert_ascii_to_bin(key), 8)
    bin_text = partion(convert_ascii_to_bin(text), 8)

    hex = ""
    for i, c in enumerate(bin_text):
        hex += xor(c, bin_key[i % len(key)])

    return convert_bin_to_hex(hex)
