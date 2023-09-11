import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES

class DecryptTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Decrypt Tool")

        self.label = tk.Label(root, text="enter the key ")
        self.label.pack()

        self.key1_label = tk.Label(root, text="key1:")
        self.key1_label.pack()
        self.key1_entry = tk.Entry(root)
        self.key1_entry.pack()

        self.key2_label = tk.Label(root, text="key2")
        self.key2_label.pack()
        self.key2_entry = tk.Entry(root)
        self.key2_entry.pack()

        self.key3_label = tk.Label(root, text="key3:")
        self.key3_label.pack()
        self.key3_entry = tk.Entry(root)
        self.key3_entry.pack()

        self.open_button = tk.Button(root, text=" open file", command=self.open_file)
        self.open_button.pack()

        self.decrypt_button = tk.Button(root, text=" decrypt", command=self.decrypt_and_save)
        self.decrypt_button.pack()

    def open_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_entry = tk.Entry(self.root)
            self.file_entry.insert(0, self.file_path)
            self.file_entry.pack()

    def decrypt_and_save(self):
        file_path = self.file_entry.get()
        key1 = self.key1_entry.get()
        key2 = self.key2_entry.get()
        key3 = self.key3_entry.get()

        if file_path and key1 and key2 and key3:
            with open(file_path, "rb") as file:
                firmware = file.read()

            decrypted_firmware = self.decrypt_with_keys(firmware, key1, key2, key3)

            save_path = filedialog.asksaveasfilename(defaultextension=".dec.bin")
            if save_path:
                with open(save_path, "wb") as save_file:
                    save_file.write(decrypted_firmware)

    def decrypt_with_keys(self, firmware, key1, key2, key3):
        aes = AES.new(key1.encode(), AES.MODE_ECB)
        decrypted_firmware = aes.decrypt(firmware)
        aes = AES.new(key2.encode(), AES.MODE_ECB)
        decrypted_firmware = aes.decrypt(decrypted_firmware)
        aes = AES.new(key3.encode(), AES.MODE_ECB)
        decrypted_firmware = aes.decrypt(decrypted_firmware)
        return decrypted_firmware

if __name__ == "__main__":
    root = tk.Tk()
    app = DecryptTool(root)
    root.mainloop()
