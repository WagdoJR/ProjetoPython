!pip install pillow cryptography

from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import sys

# Função para embutir texto em uma imagem (opção 1)
def embutir_texto_em_imagem(texto, caminho_imagem):
    try:
        # Carregar imagem
        imagem = Image.open(caminho_imagem)
        imagem.convert("RGB")

        largura, altura = imagem.size
        pixels = imagem.load()

        # Embutir o texto nos pixels da imagem
        texto_bin = ''.join([format(ord(i), '08b') for i in texto])
        idx = 0

        for y in range(altura):
            for x in range(largura):
                if idx < len(texto_bin):
                    r, g, b = pixels[x, y]
                    r = (r & ~1) | int(texto_bin[idx])
                    pixels[x, y] = (r, g, b)
                    idx += 1
                else:
                    break

        imagem.save("imagem_embutida.png")
        print("Texto embutido com sucesso em 'imagem_embutida.png'")
    except Exception as e:
        print(f"Erro ao embutir texto na imagem: {e}")

# Função para recuperar texto de uma imagem (opção 2)
def recuperar_texto_de_imagem(caminho_imagem):
    try:
        imagem = Image.open(caminho_imagem)
        largura, altura = imagem.size
        pixels = imagem.load()

        texto_bin = ""

        for y in range(altura):
            for x in range(largura):
                r, g, b = pixels[x, y]
                texto_bin += str(r & 1)

        texto = ''.join([chr(int(texto_bin[i:i+8], 2)) for i in range(0, len(texto_bin), 8)])
        print(f"Texto recuperado: {texto}")
    except Exception as e:
        print(f"Erro ao recuperar texto da imagem: {e}")

# Função para gerar hash da imagem (opção 3)
def gerar_hash_imagem(caminho_imagem):
    try:
        with open(caminho_imagem, "rb") as f:
            bytes = f.read()
            hash = hashlib.sha256(bytes).hexdigest()
            print(f"Hash SHA-256 da imagem: {hash}")
            return hash
    except Exception as e:
        print(f"Erro ao gerar hash da imagem: {e}")

# Função para encriptar uma mensagem (opção 4)
def encriptar_mensagem(mensagem, chave_publica):
    ciphertext = chave_publica.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Mensagem encriptada com sucesso.")
    # Encode ciphertext to base64 for safe handling as string
    ciphertext_b64 = base64.b64encode(ciphertext).decode() 
    return ciphertext_b64

# Função para decriptar uma mensagem (opção 5)
def decriptar_mensagem(mensagem_encriptada, chave_privada):
    # Decode base64 encoded ciphertext back to bytes
    mensagem_encriptada_bytes = base64.b64decode(mensagem_encriptada)  
    plaintext = chave_privada.decrypt(
        mensagem_encriptada_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Mensagem decriptada: {plaintext.decode()}")
    return plaintext.decode()

# Gerar chaves pública e privada
def gerar_chaves():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica

# Função do menu principal
def menu():
    chave_privada, chave_publica = gerar_chaves()
    while True:
        print("\nMenu de Opções:")
        print("(1) Embutir texto em uma imagem usando Steganography")
        print("(2) Recuperar texto de uma imagem com Steganography")
        print("(3) Gerar hash das imagens original e alterada")
        print("(4) Encriptar uma mensagem com criptografia de chave pública e privada")
        print("(5) Decriptar uma mensagem com criptografia de chave pública e privada")
        print("(S ou s) Sair")

        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            texto = input("Digite o texto a ser embutido: ")
            caminho_imagem = input("Digite o caminho da imagem: ")
            embutir_texto_em_imagem(texto, caminho_imagem)

        elif opcao == "2":
            caminho_imagem = input("Digite o caminho da imagem alterada: ")
            recuperar_texto_de_imagem(caminho_imagem)

        elif opcao == "3":
            caminho_imagem_original = input("Digite o caminho da imagem original: ")
            caminho_imagem_alterada = input("Digite o caminho da imagem alterada: ")
            print("Hash da imagem original:")
            gerar_hash_imagem(caminho_imagem_original)
            print("Hash da imagem alterada:")
            gerar_hash_imagem(caminho_imagem_alterada)

        elif opcao == "4":
            mensagem = input("Digite a mensagem a ser encriptada: ")
            mensagem_encriptada = encriptar_mensagem(mensagem, chave_publica)
            print(f"Mensagem encriptada (base64): {mensagem_encriptada}") # Indicate base64 encoding

        elif opcao == "5":
            mensagem_encriptada = input("Digite a mensagem encriptada (base64): ") # Indicate base64 encoding
            decriptar_mensagem(mensagem_encriptada, chave_privada)

        elif opcao.lower() == "s":
            print("Saindo do programa...")
            break

        else:
            print("Opção inválida, tente novamente.")

# Executar o menu
menu()