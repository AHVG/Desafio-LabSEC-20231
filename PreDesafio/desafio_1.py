from utils import convert_hex_to_base64, start, finish


def main():
    start("Desafio 1")

    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = convert_hex_to_base64(hex)
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    print(f"Hex     : {hex}")
    print(f"Base64  : {base64}")
    print(f"Expected: {expected}")
    print(f"Equal   : {base64 == expected}")

    finish()


main()
