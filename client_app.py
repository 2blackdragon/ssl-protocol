import logging
import os
import pickle
import platform
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


class ClientGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title('SSL Client')
        self.window.geometry('800x450')

        self.host_label = tk.Label(self.window, text='Host:')
        self.host_label.grid(row=0, column=0, padx=5, pady=5)
        self.host_entry = tk.Entry(self.window)
        self.host_entry.insert(0, 'localhost')
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)

        self.port_label = tk.Label(self.window, text='Port:')
        self.port_label.grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = tk.Entry(self.window)
        self.port_entry.insert(0, '8443')
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        self.connect_button = tk.Button(
            self.window, text='Connect', command=self.connect
        )
        self.connect_button.grid(row=2, column=0, padx=10, pady=5)

        self.disconnect_button = tk.Button(
            self.window, text='Disconnect', command=self.disconnect
        )
        self.disconnect_button.grid(row=2, column=1, padx=10, pady=5)

        self.generate_cert_button = tk.Button(
            self.window, text='Generate Certificate', command=self.generate_certificate
        )
        self.generate_cert_button.grid(row=2, column=2, padx=10, pady=5)

        self.key_folder_label = tk.Label(self.window, text='Key Folder:')
        self.key_folder_label.grid(row=3, column=0, padx=5, pady=5)
        self.key_folder_entry = tk.Entry(self.window, width=40, state='readonly')
        self.key_folder_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5)
        self.set_key_folder_button = tk.Button(
            self.window, text='Browse', command=self.set_key_folder
        )
        self.set_key_folder_button.grid(row=3, column=3, padx=10, pady=5)

        self.message_entry = tk.Entry(self.window, width=40)
        self.message_entry.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

        self.send_button = tk.Button(
            self.window, text='Send', command=self.send_message
        )
        self.send_button.grid(row=4, column=3, padx=10, pady=5)

        self.log_text = tk.Text(self.window, height=10, state='disabled')
        self.log_text.grid(row=5, column=0, columnspan=4, padx=10, pady=10)

        self.log_file_label = tk.Label(self.window, text='Log File:')
        self.log_file_label.grid(row=6, column=0, padx=5, pady=5)
        self.log_file_entry = tk.Entry(self.window, width=40, state='readonly')
        self.log_file_entry.grid(row=6, column=1, columnspan=2, padx=5, pady=5)
        self.set_log_button = tk.Button(
            self.window, text='Browse Log', command=self.set_log
        )
        self.set_log_button.grid(row=6, column=3, padx=10, pady=5)

        self.view_log_button = tk.Button(
            self.window, text='View Log', command=self.view_log
        )
        self.view_log_button.grid(row=7, column=0, padx=10, pady=5)

        self.clear_log_button = tk.Button(
            self.window, text='Clear Log', command=self.clear_log
        )
        self.clear_log_button.grid(row=7, column=1, padx=10, pady=5)

        self.load_cert_button = tk.Button(
            self.window, text='Load Certificate', command=self.load_certificate
        )
        self.load_cert_button.grid(row=7, column=2, padx=10, pady=5)

        self.exit_button = tk.Button(self.window, text='Exit', command=self.window.quit)
        self.exit_button.grid(row=7, column=3, padx=10, pady=5)

        self.log_file = 'ssl_log.txt'
        self.key_folder = '.'
        self.cert_file = 'client_certificate.pem'
        self.private_file = 'client_private_key.pem'
        
        self.log_file_entry.configure(state='normal')
        self.log_file_entry.insert(0, self.log_file)
        self.log_file_entry.configure(state='readonly')
        
        self.key_folder_entry.configure(state='normal')
        self.key_folder_entry.insert(0, self.key_folder)
        self.key_folder_entry.configure(state='readonly')
        
        self.configure_logging()
        
        self.rsa_key = None
        self.rsa_public_key = None
        self.certificate_data = None
        self.cert_signature = None
        self.client_cert_loaded = False

        self.sock = None
        self.aes_key = None
        self.mac_key = None
        self.server_public_key = None
        self.running = False
        self.handshake_messages = []

        self.window.mainloop()

    def configure_logging(self):
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            if hasattr(handler, 'close'):
                handler.close()
        logging.basicConfig(
            filename=self.log_file,
            level=logging.DEBUG,
            format='%(asctime)s - [CLIENT] %(message)s',
        )

    def set_log(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('Text files', '*.txt'), ('All files', '*.*')],
            title='Choose Log File',
        )
        if file_path:
            self.log_file = file_path
            self.log_file_entry.configure(state='normal')
            self.log_file_entry.delete(0, tk.END)
            self.log_file_entry.insert(0, self.log_file)
            self.log_file_entry.configure(state='readonly')
            self.configure_logging()
            self.log(f'Logging configured to {self.log_file}')
        else:
            self.log('Log file selection cancelled')

    def set_key_folder(self):
        folder_path = filedialog.askdirectory(
            title='Select Folder for Certificate and Key'
        )
        if folder_path:
            self.key_folder = folder_path
            self.key_folder_entry.configure(state='normal')
            self.key_folder_entry.delete(0, tk.END)
            self.key_folder_entry.insert(0, self.key_folder)
            self.key_folder_entry.configure(state='readonly')
            self.log(f'Key folder set to {self.key_folder}')

    def generate_certificate(self):
        try:
            self.rsa_key = RSA.generate(2048)
            self.rsa_public_key = self.rsa_key.publickey()
            
            self.certificate_data = {
                'subject': 'SSL Client Certificate',
                'public_key': self.rsa_public_key.export_key(),
                'issuer': 'Self-Signed',
                'validity': '2024-2034',
                'serial_number': '2',
                'type': 'CLIENT'
            }
            
            h = SHA256.new(pickle.dumps(self.certificate_data))
            self.cert_signature = pkcs1_15.new(self.rsa_key).sign(h)
            
            private_path = os.path.join(self.key_folder, self.private_file)
            with open(private_path, 'wb') as f:
                f.write(self.rsa_key.export_key())
            
            cert_path = os.path.join(self.key_folder, self.cert_file)
            with open(cert_path, 'wb') as f:
                pickle.dump({
                    'certificate': self.certificate_data,
                    'signature': self.cert_signature
                }, f)
            
            self.client_cert_loaded = True
            self.log(f'Generated and saved certificate to {cert_path}')
            self.log(f'Saved private key to {private_path}')
            messagebox.showinfo('Success', 'Certificate generated successfully!')
            
        except Exception as e:
            self.log(f'Error generating certificate: {e}')
            messagebox.showerror('Error', f'Certificate generation failed: {e}')

    def load_certificate(self):
        try:
            cert_path = os.path.join(self.key_folder, self.cert_file)
            private_path = os.path.join(self.key_folder, self.private_file)
            
            if not os.path.exists(cert_path) or not os.path.exists(private_path):
                response = messagebox.askyesno(
                    'Certificate Not Found',
                    'Certificate or key file not found. Generate new certificate?'
                )
                if response:
                    self.generate_certificate()
                return
            
            with open(private_path, 'rb') as f:
                self.rsa_key = RSA.import_key(f.read())
            
            with open(cert_path, 'rb') as f:
                cert_data = pickle.load(f)
                self.certificate_data = cert_data['certificate']
                self.cert_signature = cert_data['signature']
                self.rsa_public_key = RSA.import_key(self.certificate_data['public_key'])
            
            h = SHA256.new(pickle.dumps(self.certificate_data))
            pkcs1_15.new(self.rsa_public_key).verify(h, self.cert_signature)
            
            self.client_cert_loaded = True
            self.log(f'Loaded certificate from {cert_path}')
            self.log(f'Certificate subject: {self.certificate_data["subject"]}')
            messagebox.showinfo('Success', 'Certificate loaded successfully!')
            
        except (ValueError, TypeError):
            self.log('Certificate signature verification failed')
            messagebox.showerror('Error', 'Certificate verification failed!')
        except Exception as e:
            self.log(f'Error loading certificate: {e}')
            messagebox.showerror('Error', f'Certificate loading failed: {e}')

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        logging.info(message)

    def connect(self):
        if self.sock:
            messagebox.showinfo('Info', 'Already connected')
            return
        
        host = self.host_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror('Error', 'Invalid port number')
            self.log('Invalid port number')
            return

        try:
            self.sock = socket.create_connection((host, port))
            self.log(f'Connected to {host}:{port}')

            # Отправка ClientHello
            client_hello = {'version': 'SSL demo version', 'ciphers': ['AES_256_CBC']}
            client_hello_data = pickle.dumps(client_hello)
            self.sock.send(client_hello_data)
            self.handshake_messages = [client_hello_data]
            self.log(
                f'Sent ClientHello: Version={client_hello["version"]}, Ciphers={client_hello["ciphers"]}'
            )

            # Получение ServerHello
            server_hello_data = self.sock.recv(1024)
            server_hello = pickle.loads(server_hello_data)
            self.handshake_messages.append(server_hello_data)
            self.log(
                f'Received ServerHello: Cipher={server_hello["cipher"]}, Client Auth Required={server_hello.get("client_auth_required", False)}'
            )

            # Проверка сертификата сервера
            server_cert_data = server_hello['server_certificate']
            server_cert = server_cert_data['certificate']
            server_signature = server_cert_data['signature']
            
            # Проверяем тип сертификата
            if server_cert.get('type') != 'SERVER':
                self.log('Invalid server certificate type')
                raise ValueError('Invalid server certificate type')
            
            server_pub_key = RSA.import_key(server_cert['public_key'])
            
            # Проверка подписи сертификата
            h_cert = SHA256.new(pickle.dumps(server_cert))
            try:
                pkcs1_15.new(server_pub_key).verify(h_cert, server_signature)
                self.log('Server certificate verified (self-signed)')
                self.log(f'Server certificate subject: {server_cert["subject"]}')
            except (ValueError, TypeError):
                self.log('Server certificate verification failed')
                raise ValueError('Invalid server certificate')
            
            self.server_public_key = server_pub_key

            # Если сервер требует аутентификацию клиента, отправляем клиентский сертификат
            if server_hello.get('client_auth_required', False):
                if not self.client_cert_loaded:
                    self.log('Server requires client authentication but no client certificate loaded')
                    response = messagebox.askyesno(
                        'Client Certificate Required',
                        'Server requires client certificate. Load or generate certificate now?'
                    )
                    if response:
                        self.load_certificate()
                    else:
                        raise ValueError('Client certificate required but not available')
                
                if not self.client_cert_loaded:
                    raise ValueError('Client certificate not available')
                
                # Отправка клиентского сертификата
                client_cert_package = {
                    'certificate': self.certificate_data,
                    'signature': self.cert_signature
                }
                self.sock.send(pickle.dumps(client_cert_package))
                self.handshake_messages.append(pickle.dumps(client_cert_package))
                
                h = SHA256.new(b''.join(self.handshake_messages))
                signature = pkcs1_15.new(self.rsa_key).sign(h)
                self.sock.send(signature)
                self.handshake_messages.append(signature)
                self.log('Sent client certificate and handshake signature')

            # Генерация и отправка сессионных ключей
            self.aes_key = get_random_bytes(32)
            self.mac_key = get_random_bytes(32)
            combined_keys = self.aes_key + self.mac_key
            rsa_cipher = PKCS1_OAEP.new(self.server_public_key)
            encrypted_keys = rsa_cipher.encrypt(combined_keys)
            self.sock.send(encrypted_keys)
            self.handshake_messages.append(encrypted_keys)
            self.log('Sent encrypted AES and MAC keys')

            # Получение Server Finished
            server_finished = self.sock.recv(32)
            expected_hash = SHA256.new(b''.join(self.handshake_messages)).digest()
            if server_finished != expected_hash:
                self.log('Server Finished verification failed')
                raise ValueError('Invalid Server Finished message')
            self.log('Received and verified Server Finished')

            # Отправка Client Finished
            finished_hash = SHA256.new(b''.join(self.handshake_messages)).digest()
            self.sock.send(finished_hash)
            self.log(f'Sent Client Finished: {finished_hash.hex()}')

            # Получение подтверждения завершения рукопожатия
            handshake_response = self.sock.recv(1024).decode()
            self.log(f'Handshake response: {handshake_response}')

            self.running = True
            self.receive_thread = threading.Thread(
                target=self.receive_messages, daemon=True
            )
            self.receive_thread.start()
            
        except Exception as e:
            messagebox.showerror('Error', f'Connection failed: {e}')
            self.log(f'Connection error: {e}')
            if self.sock:
                self.sock.close()
                self.sock = None

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        padded_message = pad(message.encode(), 16)
        ciphertext = cipher.encrypt(padded_message)
        mac = HMAC.new(self.mac_key, ciphertext, SHA256).digest()
        encrypted_data = cipher.iv + ciphertext + mac
        self.log(f'Encrypted data: {encrypted_data.hex()}')
        return encrypted_data

    def decrypt_message(self, data):
        iv = data[:16]
        ciphertext = data[16:-32]
        received_mac = data[-32:]
        expected_mac = HMAC.new(self.mac_key, ciphertext, SHA256).digest()
        if received_mac != expected_mac:
            self.log('MAC verification failed')
            raise ValueError('Invalid MAC')
        self.log('MAC verified successfully')
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
        padded_message = cipher.decrypt(ciphertext)
        return unpad(padded_message, 16).decode()

    def receive_messages(self):
        while self.running and self.sock:
            try:
                data = self.sock.recv(1024)
                if not data:
                    self.log('Server disconnected')
                    self.disconnect()
                    break
                message = self.decrypt_message(data)
                self.log(f'Received (encrypted): {data.hex()}')
                self.log(f'Decrypted: {message}')
            except Exception as e:
                if self.running:
                    self.log(f'Receive error: {e}')
                    self.disconnect()
                    break

    def send_message(self):
        if not self.sock or not self.aes_key:
            messagebox.showerror('Error', 'Not connected or no session key')
            return
        message = self.message_entry.get()
        if message:
            try:
                encrypted_message = self.encrypt_message(message)
                self.sock.send(encrypted_message)
                self.log(f'Sent (encrypted): {encrypted_message.hex()}')
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                self.log(f'Send error: {e}')
                messagebox.showerror('Error', f'Send error: {e}')

    def disconnect(self):
        if self.sock:
            self.running = False
            self.sock.close()
            self.sock = None
            self.aes_key = None
            self.mac_key = None
            self.receive_thread = None
            self.log('Disconnected')

    def view_log(self):
        log_file = self.log_file
        if not os.path.exists(log_file):
            messagebox.showerror('Error', 'Log file does not exist')
            self.log('Log file does not exist')
            return
        try:
            if platform.system() == 'Windows':
                os.startfile(log_file)
            elif platform.system() == 'Linux':
                subprocess.run(['xdg-open', log_file])
            elif platform.system() == 'Darwin':
                subprocess.run(['open', log_file])
            else:
                messagebox.showerror('Error', 'Unsupported platform for opening log')
        except Exception as e:
            messagebox.showerror('Error', f'Cannot open log: {e}')
            self.log(f'Error opening log: {e}')

    def clear_log(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')


if __name__ == '__main__':
    ClientGUI()