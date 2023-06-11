from utils import decrypt_by_single_byte, convert_bin_to_ascii, start, finish


def main():
    start("Desafio 3")

    text, key, score = decrypt_by_single_byte(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    print(f"Text : {text}")
    print(f"Key  : {convert_bin_to_ascii(key)}")
    print(f"Score: {score}")

    finish()


main()
