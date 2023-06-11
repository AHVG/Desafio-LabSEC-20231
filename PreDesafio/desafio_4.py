from utils import decrypt_by_single_byte, convert_bin_to_ascii, read_file, start, finish


def main():

    start("Desafio 4")

    scores, texts, keys = [], [], []
    for line in read_file("4.txt"):
        t, k, s = decrypt_by_single_byte(line)
        texts.append(t), keys.append(k), scores.append(s)
    index = scores.index(max(scores))

    print(f"Text : {texts[index]}")
    print(f"Key  : {convert_bin_to_ascii(keys[index])}")
    print(f"Score: {scores[index]}")

    finish()


main()
