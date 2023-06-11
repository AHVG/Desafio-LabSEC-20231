
from utils import xor_hex, start, finish


def main():
    start("Desafio 2")

    hex1 = "1c0111001f010100061a024b53535009181c"
    hex2 = "686974207468652062756c6c277320657965"
    hex = xor_hex(hex1, hex2)
    expected = "746865206b696420646f6e277420706c6179"

    print(f"Hex1    : {hex1}")
    print(f"Hex2    : {hex2}")
    print(f"Hex     : {hex}")
    print(f"Expected: {expected}")
    print(f"Equal   : {hex == expected}")

    finish()


main()
