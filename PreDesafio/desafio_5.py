from utils import repeting_key_xor, start, finish


def main():
    start("Desafio 5")

    text = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    key = "ICE"
    hex = repeting_key_xor(text, key)
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    print(f"Text    : {text}")
    print(f"Key     : {key}")
    print(f"Hex     : {hex}")
    print(f"Expected: {expected}")
    print(f"Equal   : {hex == expected}")

    finish()


main()
