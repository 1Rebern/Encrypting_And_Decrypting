import sys
import os
import re
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtCore import QObject, Slot, Signal

class AlphabetBuilder:
    def __init__(self):
        self.alphabet = {}

    def add_alphabet(self, name, characters):
        self.alphabet[name] = characters
        return self

    def build(self):
        return self.alphabet

abc = (
    AlphabetBuilder()
    .add_alphabet("en", 'abcdefghijklmnopqrstuvwxyz')
    .add_alphabet("en_upper", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    .add_alphabet("ua", 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя')
    .add_alphabet("ua_upper", 'АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ')
    .add_alphabet("num", '0123456789')
    .add_alphabet("special", '@!"#$%&\'()*+,-./:;<=>&[\\]^_`{|}~')
    .build()
)


class Caesar:
    def __init__(self):
        self.remove_spaces_choice = False
        self.uppercase_choice = False

    def format_key(self, keys):
        return f"\nКлюч: ~~~{keys['u']}u{keys['e']}e{keys['n']}n{keys['s']}s"

    @staticmethod
    def get_full_path(filename):
        folder_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(folder_path, filename)

    def extract_keys(self, encrypted_message):
        keys_info = re.findall(r'Ключ: ~~~(\d+)u(\d+)e(\d+)n(\d+)s', encrypted_message)

        if keys_info:
            return {'u': int(keys_info[0][0]), 'e': int(keys_info[0][1]), 'n': int(keys_info[0][2]), 's': int(keys_info[0][3])}
        else:
            print("Файл не містить інформації про ключі.")
            return None

    def print_keys_info(self, keys):
        print(f"Знайдені ключі: Українська - {keys['u']}, Англійська - {keys['e']}, Числа - {keys['n']}, Спеціальні символи - {keys['s']}")

    def has_cyrillic_or_special(self, text, charset):
        return bool(re.search(charset, text))

    def detect_languages(self, text):
        has_ukrainian = self.has_cyrillic_or_special(text, '[а-яА-Я]')
        has_english = self.has_cyrillic_or_special(text, '[a-zA-Z]')
        has_numbers = self.has_cyrillic_or_special(text, '[0-9]')
        has_special = self.has_cyrillic_or_special(text, '[@!"#$%&\'()*+,-./:;<=>&[\\]^_`{|}~]')
        return has_ukrainian, has_english, has_numbers, has_special

    def encrypt_ua(self, letter, keys):
        if letter in abc['ua']:
            idx = abc['ua'].index(letter)
            new_idx = (idx + keys['u']) % len(abc['ua'])
            return abc['ua'][new_idx]
        elif self.uppercase_choice and letter in abc['ua_upper']:
            idx = abc['ua_upper'].index(letter)
            new_idx = (idx + keys['u']) % len(abc['ua_upper'])
            return abc['ua_upper'][new_idx]
        else:
            return letter

    def encrypt_en(self, letter, keys):
        if letter in abc['en']:
            idx = abc['en'].index(letter)
            new_idx = (idx + keys['e']) % len(abc['en'])
            return abc['en'][new_idx]
        elif self.uppercase_choice and letter in abc['en_upper']:
            idx = abc['en_upper'].index(letter)
            new_idx = (idx + keys['e']) % len(abc['en_upper'])
            return abc['en_upper'][new_idx]
        else:
            return letter

    def encrypt(self, message, keys, remove_spaces, keep_uppercase, encrypt_numbers=False, encrypt_special=False):
        if remove_spaces:
            message = message.replace(' ', '')

        message = message.lower() if keep_uppercase else message

        has_ukrainian, has_english, has_numbers, has_special = self.detect_languages(message)

        encrypted_msg = ''

        for letter in message:
            if has_ukrainian and letter in abc['ua']:
                encrypted_msg += self.encrypt_ua(letter, keys)
            elif has_english and letter in abc['en']:
                encrypted_msg += self.encrypt_en(letter, keys)
            elif has_numbers and letter in abc['num']:
                encrypted_msg += abc['num'][(abc['num'].index(letter) + keys['n']) % len(abc['num'])] if encrypt_numbers else letter
            elif has_special and letter in abc['special']:
                encrypted_msg += abc['special'][(abc['special'].index(letter) + keys['s']) % len(abc['special'])] if encrypt_special else letter
            else:
                encrypted_msg += letter

        encrypted_msg += self.format_key(keys)

        return encrypted_msg

    def decrypt_ua(self, letter, keys):
        if letter in abc['ua']:
            idx = abc['ua'].index(letter)
            new_idx = (idx - keys['u']) % len(abc['ua'])
            return abc['ua'][new_idx]
        elif self.uppercase_choice and letter in abc['ua_upper']:
            idx = abc['ua_upper'].index(letter)
            new_idx = (idx - keys['u']) % len(abc['ua_upper'])
            return abc['ua_upper'][new_idx]
        else:
            return letter

    def decrypt_en(self, letter, keys):
        if letter in abc['en']:
            idx = abc['en'].index(letter)
            new_idx = (idx - keys['e']) % len(abc['en'])
            return abc['en'][new_idx]
        elif self.uppercase_choice and letter in abc['en_upper']:
            idx = abc['en_upper'].index(letter)
            new_idx = (idx - keys['e']) % len(abc['en_upper'])
            return abc['en_upper'][new_idx]
        else:
            return letter

    def decrypt(self, message, keys, remove_spaces=True, keep_uppercase=True, decrypt_numbers=True, decrypt_special=True):
        has_ukrainian, has_english, has_numbers, has_special = self.detect_languages(message)

        message = re.sub(r'\n+Ключ: ~~~\d+u\d+e\d+n\d+s', '', message)

        decrypted_msg = ''

        for letter in message:
            if has_ukrainian and letter in abc['ua']:
                decrypted_msg += self.decrypt_ua(letter, keys)
            elif has_english and letter in abc['en']:
                decrypted_msg += self.decrypt_en(letter, keys)
            elif has_numbers and letter in abc['num']:
                decrypted_msg += abc['num'][(abc['num'].index(letter) - keys['n']) % len(abc['num'])] if decrypt_numbers else letter
            elif has_special and letter in abc['special']:
                decrypted_msg += abc['special'][(abc['special'].index(letter) - keys['s']) % len(abc['special'])] if decrypt_special else letter
            else:
                decrypted_msg += letter

        return decrypted_msg, keys

    def read_file(self, filename):
        full_path = self.get_full_path(filename)
        try:
            with open(full_path, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            print(f"Файл {filename} не знайдено за шляхом {full_path}. Завершення програми.")
            return None

    def write_file(self, filename, content):
        full_path = self.get_full_path(filename)
        with open(full_path, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Зміст файлу збережено у файлі {full_path}")

    def get_keys_from_user(self, has_ukrainian, has_english, has_numbers, has_special):
        keys = {
            'u': random.randint(50, 232) if has_ukrainian else 0,
            'e': random.randint(50, 232) if has_english else 0,
            'n': random.randint(50, 232) if has_numbers else 0,
            's': random.randint(50, 232) if has_special else 0,
        }

        return keys

    def get_user_preferences(self, spaces, uppercase):
        self.remove_spaces_choice = spaces
        self.uppercase_choice = uppercase

        print(f"Remove Spaces Choice: {self.remove_spaces_choice}")
        print(f"Uppercase Choice: {self.uppercase_choice}")

        return self.remove_spaces_choice, self.uppercase_choice

    def get_output_filename(self, filename, operation, save_to_separate_file):
        if save_to_separate_file:
            return f"{operation}_{filename}"
        return filename

    def process_file(self, filename, operation, save_to_separate_file=False):
        text_to_check = self.read_file(filename)
        if text_to_check is None:
            print("Не вдалося отримати вміст файлу. Завершення програми.")
            return

        output_filename = self.get_output_filename(filename, operation, save_to_separate_file)

        msg = text_to_check

        if msg is not None:
            has_ukrainian, has_english, has_numbers, has_special = self.detect_languages(msg)

            self.remove_spaces_choice, self.uppercase_choice = self.get_user_preferences(self.remove_spaces_choice, self.uppercase_choice)

            if operation == "encrypt":
                keys = self.get_keys_from_user(has_ukrainian, has_english, has_numbers, has_special)
                if keys is not None:
                    encrypted_msg = self.encrypt(
                        msg,
                        keys,
                        self.remove_spaces_choice,
                        self.uppercase_choice,
                        has_numbers,
                        has_special
                    )
                    if save_to_separate_file:
                        self.write_file(output_filename, encrypted_msg)
                    else:
                        self.write_file(filename, encrypted_msg)

            elif operation == "decrypt":
                keys = self.extract_keys(msg)
                if keys is not None:
                    decrypted_msg, used_keys = self.decrypt(
                        msg,
                        keys,
                        self.remove_spaces_choice == '1',
                        self.uppercase_choice == '1',
                        has_numbers,
                        has_special
                    )
                    if save_to_separate_file:
                        self.write_file(output_filename, decrypted_msg)
                        self.print_keys_info(used_keys)
                    else:
                        self.write_file(filename, decrypted_msg)
                        self.print_keys_info(used_keys)

            else:
                print("Невірна операція. Завершення програми.")


class RSA:
    @staticmethod
    def get_full_path(filename):
        folder_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(folder_path, filename)

    @staticmethod
    def generate_key_pair(key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def save_private_key(private_key, filename="private_key.pem"):
        filename = RSA.get_full_path(filename)
        with open(filename, 'wb') as file:
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            file.write(private_key_bytes)

    @staticmethod
    def load_private_key(filename="private_key.pem"):
        filename = RSA.get_full_path(filename)
        with open(filename, 'rb') as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None
            )
        return private_key

    @staticmethod
    def encrypt_file(input_file, output_file, public_key):
        input_file = RSA.get_full_path(input_file)
        output_file = RSA.get_full_path(output_file)

        with open(input_file, 'rb') as file:
            plaintext = file.read()

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_file, 'wb') as file:
            file.write(ciphertext)

    @staticmethod
    def decrypt_file(input_file, output_file, private_key):
        input_file = RSA.get_full_path(input_file)
        output_file = RSA.get_full_path(output_file)

        with open(input_file, 'rb') as file:
            ciphertext = file.read()

        decrypted_message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_file, 'wb') as file:
            file.write(decrypted_message)

    @staticmethod
    def process_file_RSA(filename, operation, key_size=2048, key_filename="private_key.pem"):
        print(f"File name RSA: {filename}")
        print(f"Key size RSA: {key_size}")

        if operation == "encrypt":
            private_key, public_key = RSA.generate_key_pair(key_size)

            RSA.save_private_key(private_key)
            output_filename = f"encrypted_{filename}"
            RSA.encrypt_file(filename, output_filename, public_key)
            print(f"Encryption completed. Encrypted file saved to {output_filename}")

        elif operation == "decrypt":
            private_key = RSA.load_private_key(key_filename)
            output_filename = f"decrypted_{filename}"
            RSA.decrypt_file(filename, output_filename, private_key)
            print(f"Decryption completed. Decrypted file saved to {output_filename}")

        else:
            print("Invalid operation. Program terminated.")


class MainWindow(QObject):
    def __init__(self):
        QObject.__init__(self)

    @staticmethod
    def get_full_path(filename):
        folder_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(folder_path, filename)

    signalFilename = Signal(str)
    signalSpace = Signal(bool)
    signalCapital = Signal(bool)
    signalSelectE = Signal(bool)
    signalSave = Signal(bool)

    @Slot(str, bool, bool, bool)
    def checkChoiseE(self, getFilename, getSpace, getCapital, getSave):
        caesar_instance = Caesar()
        spaces = False
        uppercase = False
        save_to_separate_file = False
        filename = ""

        if getSpace and getCapital:
            spaces = True
            uppercase = True 

        elif getSpace:
            spaces = True

        elif getCapital:
            uppercase = True

        if getSave:
            save_to_separate_file = True

        expected_filename_pattern = re.compile(r".+\.(txt|py)", re.IGNORECASE)

        if expected_filename_pattern.match(getFilename):
            full_path = self.get_full_path(getFilename)

            if os.path.exists(full_path):
                filename = getFilename

                print("Nice")
                print("Remove Spaces Choice:", spaces)
                print("Uppercase Choice:", uppercase)
                
                caesar_instance.get_user_preferences(spaces, uppercase)

                self.signalSelectE.emit(True)

            else:
                self.signalSelectE.emit(False)
                print("File does not exist:", full_path)
        else:
            self.signalSelectE.emit(False)
            print(getFilename)
            print("Not Nice")

        caesar_instance.process_file(filename, "encrypt", save_to_separate_file)


    signalSelectD = Signal(bool)

    @Slot(str, bool)
    def checkChoiseD(self, getFilename, getSave):
        caesar_instance = Caesar()
        save_to_separate_file = False
        filename = ""

        if getSave:
            save_to_separate_file = True

        expected_filename_pattern = re.compile(r".+\.(txt|py)", re.IGNORECASE)

        if expected_filename_pattern.match(getFilename):
            full_path = self.get_full_path(getFilename)

            if os.path.exists(full_path):
                filename = getFilename
                print("Nice")
                self.signalSelectD.emit(True)
            else:
                self.signalSelectD.emit(False)
                print("File does not exist:", full_path)
        else:
            self.signalSelectD.emit(False)
            print(getFilename)
            print("Not Nice")

        caesar_instance.process_file(filename, "decrypt", save_to_separate_file)

    signalFilenameRSA = Signal(str)
    signalKey = Signal(str)
    signalSelectERSA = Signal(bool)

    @Slot(str, str)
    def checkChoiseRSAE(self, getFilenameRSA, getKey):
        filenameRSA = ''
        keyRSA = 0
        rsa_instance = RSA()

        expected_filename_pattern = re.compile(r".+\.txt", re.IGNORECASE)

        if expected_filename_pattern.match(getFilenameRSA):
            full_path = self.get_full_path(getFilenameRSA)

            if os.path.exists(full_path):
                if getKey.isdigit():
                    try:
                        keyRSA = int(getKey)
                        if keyRSA % 2 == 0 and keyRSA >= 2048:
                            filenameRSA = getFilenameRSA
                            print("Nice")
                            print(f"Key size: {keyRSA}")
                            rsa_instance.process_file_RSA(filenameRSA, "encrypt", keyRSA)
                            
                            self.signalSelectERSA.emit(True)
                        else:
                            raise ValueError("Invalid key size")
                    except ValueError as e:
                        self.signalSelectERSA.emit(False)
                        print(f"Invalid key: {e}")
                else:
                    self.signalSelectERSA.emit(False)
                    print("Invalid key format")
            else:
                self.signalSelectERSA.emit(False)
                print(f"File does not exist: {filenameRSA}")
        else:
            self.signalSelectERSA.emit(False)
            print("Not Nice")

    signalSelectDRSA = Signal(bool)
    signalKeyFilename = Signal(str)
    @Slot(str, str)
    def checkChoiseRSAD(self, getFilenameRSA, getKeyFilename):
        filenameRSA = ''
        keyfilename = ''
        rsa_instance = RSA()
        print(f"Filename1: {getFilenameRSA}")
        print(f"Key file: {getKeyFilename}")

        expected_filename_pattern = re.compile(r".+\.txt", re.IGNORECASE)
        expected_keyfile_pattern = re.compile(r".+\.pem", re.IGNORECASE)

        if expected_filename_pattern.match(getFilenameRSA):
            full_path = self.get_full_path(getFilenameRSA)

            if os.path.exists(full_path):
                if expected_keyfile_pattern.match(getKeyFilename):
                    keyfilename = self.get_full_path(getKeyFilename)

                    if os.path.exists(keyfilename):
                        print("Nice")
                        keyfilename = getKeyFilename
                        filenameRSA = getFilenameRSA
                        print(f"Filename2: {filenameRSA}")
                        print(f"Key file: {keyfilename}")

                        rsa_instance.process_file_RSA(filenameRSA, "decrypt", keyfilename)

                        self.signalSelectDRSA.emit(True)
                    else:
                        self.signalSelectDRSA.emit(False)
                        print(f"Key file does not exist: {keyfilename}")
                else:
                    self.signalSelectDRSA.emit(False)
                    print("Invalid key file extension")
            else:
                self.signalSelectDRSA.emit(False)
                print("File does not exist:", full_path)
        else:
            self.signalSelectDRSA.emit(False)
            print(getFilenameRSA)
            print("Not Nice")

if __name__ == "__main__":
    app = QGuiApplication(sys.argv)
    engine = QQmlApplicationEngine()

    #бек для основи
    main = MainWindow()
    engine.rootContext().setContextProperty("backend", main)

    #завантаженя основного вікна
    engine.load(os.path.join(os.path.dirname(__file__), "qml/main.qml"))

    if not engine.rootObjects():
        sys.exit(-1)
    sys.exit(app.exec())