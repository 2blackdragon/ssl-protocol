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
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


class ServerGUI:
    def __init__(self) -> None:
        self.window = tk.Tk()
        self.window.title('SSL Server')
        self.window.geometry('850x400')

        self.log_text = tk.Text(self.window, height=10, state='disabled')
        self.log_text.grid(row=0, column=0, columnspan=4, padx=10, pady=10)

        self.message_entry = tk.Entry(self.window, width=40)
        self.message_entry.grid(row=1, column=0, columnspan=3, padx=10, pady=5)

        self.send_button = tk.Button(
            self.window, text='Send', command=self.send_message
        )
        self.send_button.grid(row=1, column=3, padx=10, pady=5)

        self.start_button = tk.Button(
            self.window, text='Start Server', command=self.start_server
        )
        self.start_button.grid(row=2, column=0, padx=10, pady=5)

        self.stop_button = tk.Button(
            self.window, text='Stop Server', command=self.stop_server
        )
        self.stop_button.grid(row=2, column=1, padx=10, pady=5)

        self.client_auth_var = tk.BooleanVar(value=False)
        self.client_auth_check = tk.Checkbutton(
            self.window,
            text='Enable Client Authentication',
            variable=self.client_auth_var,
        )
        self.client_auth_check.grid(row=2, column=2, padx=10, pady=5)

        self.generate_cert_button = tk.Button(
            self.window, text='Generate Certificate', command=self.generate_certificate
        )
        self.generate_cert_button.grid(row=2, column=3, padx=10, pady=5)

        self.key_folder_label = tk.Label(self.window, text='Key Folder:')
        self.key_folder_label.grid(row=3, column=0, padx=5, pady=5)
        self.key_folder_entry = tk.Entry(self.window, width=40, state='readonly')
        self.key_folder_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5)
        self.set_key_folder_button = tk.Button(
            self.window, text='Browse', command=self.set_key_folder
        )
        self.set_key_folder_button.grid(row=3, column=3, padx=10, pady=5)

        self.log_file_label = tk.Label(self.window, text='Log File:')
        self.log_file_label.grid(row=4, column=0, padx=5, pady=5)
        self.log_file_entry = tk.Entry(self.window, width=40, state='readonly')
        self.log_file_entry.grid(row=4, column=1, columnspan=2, padx=5, pady=5)
        self.set_log_button = tk.Button(
            self.window, text='Browse Log', command=self.set_log
        )
        self.set_log_button.grid(row=4, column=3, padx=10, pady=5)

        self.view_log_button = tk.Button(
            self.window, text='View Log', command=self.view_log
        )
        self.view_log_button.grid(row=5, column=0, padx=10, pady=5)

        self.clear_log_button = tk.Button(
            self.window, text='Clear Log', command=self.clear_log
        )
        self.clear_log_button.grid(row=5, column=1, padx=10, pady=5)

        self.load_cert_button = tk.Button(
            self.window, text='Load Certificate', command=self.load_certificate
        )
        self.load_cert_button.grid(row=5, column=2, padx=10, pady=5)

        self.exit_button = tk.Button(self.window, text='Exit', command=self.exit)
        self.exit_button.grid(row=5, column=3, padx=10, pady=5)

        self.log_file = 'ssl_log.txt'
        self.key_folder = '.'
        self.cert_file = 'server_certificate.pem'
        self.private_file = 'server_private_key.pem'
        
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
        self.rsa_cipher = None
        self.server_cert_loaded = False

        self.server_running = False
        self.server_socket = None
        self.client_threads = []
        self.ssl_sock = None
        self.aes_key = None
        self.mac_key = None
        self.handshake_messages = []

        self.window.mainloop()

    def configure_logging(self) -> None:
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            if hasattr(handler, 'close'):
                handler.close()
        logging.basicConfig(
            filename=self.log_file,
            level=logging.DEBUG,
            format='%(asctime)s - [SERVER] %(message)s',
        )

    def set_log(self) -> None:
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

    def set_key_folder(self) -> None:
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

    def generate_certificate(self) -> None:
        try:
            self.rsa_key = RSA.generate(2048)
            self.rsa_public_key = self.rsa_key.publickey()
            
            self.certificate_data = {
                'subject': 'SSL Server Certificate',
                'public_key': self.rsa_public_key.export_key(),
                'issuer': 'Self-Signed',
                'validity': '2024-2034',
                'serial_number': '1',
                'type': 'SERVER'
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
            
            self.rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
            self.server_cert_loaded = True
            self.log(f'Generated and saved certificate to {cert_path}')
            self.log(f'Saved private key to {private_path}')
            messagebox.showinfo('Success', 'Certificate generated successfully!')
            
        except Exception as e:
            self.log(f'Error generating certificate: {e}')
            messagebox.showerror('Error', f'Certificate generation failed: {e}')

    def load_certificate(self) -> None:
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
            
            self.rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
            self.server_cert_loaded = True
            self.log(f'Loaded certificate from {cert_path}')
            self.log(f'Certificate subject: {self.certificate_data["subject"]}')
            messagebox.showinfo('Success', 'Certificate loaded successfully!')
            
        except (ValueError, TypeError):
            self.log('Certificate signature verification failed')
            messagebox.showerror('Error', 'Certificate verification failed!')
        except Exception as e:
            self.log(f'Error loading certificate: {e}')
            messagebox.showerror('Error', f'Certificate loading failed: {e}')

    def log(self, message: str) -> None:
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        logging.info(message)

    def start_server(self) -> None:
        if self.server_running:
            messagebox.showinfo('Info', 'Server already running')
            return
        
        # Проверка наличия сертификата
        if not self.server_cert_loaded:
            response = messagebox.askyesno(
                'Certificate Required',
                'No certificate loaded. Load or generate certificate first?'
            )
            if response:
                self.load_certificate()
            else:
                return
        
        if not self.server_cert_loaded:
            messagebox.showerror('Error', 'Certificate is required to start server')
            return
            
        self.server_running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        threading.Thread(target=self.run_server, daemon=True).start()
        self.log('Server started')

    def run_server(self) -> None:
        try:
            self.server_socket.bind(('localhost', 8443))
            self.server_socket.listen(5)
            self.log('Server listening on localhost:8443')
        except Exception as e:
            self.log(f'Error binding socket: {e}')
            messagebox.showerror('Error', f'Bind error: {e}')
            self.server_running = False
            return

        while self.server_running:
            try:
                conn, addr = self.server_socket.accept()
                self.log(f'Connection from {addr}')
                self.ssl_sock = conn
                client_thread = threading.Thread(
                    target=self.handle_client, args=(conn, addr), daemon=True
                )
                client_thread.start()
                self.client_threads.append(client_thread)
            except Exception as e:
                if self.server_running:
                    self.log(f'Error accepting connection: {e}')

    def handle_client(self, conn, addr):
        try:
            # Получение ClientHello
            client_hello_data = conn.recv(1024)
            client_hello = pickle.loads(client_hello_data)
            self.handshake_messages = [client_hello_data]
            self.log(
                f'Received ClientHello: Version={client_hello["version"]}, Ciphers={client_hello["ciphers"]}'
            )

            # Отправка ServerHello с сертификатом сервера
            server_hello = {
                'version': 'SSL demo',
                'cipher': 'AES_256_CBC',
                'server_certificate': {
                    'certificate': self.certificate_data,
                    'signature': self.cert_signature
                },
                'client_auth_required': self.client_auth_var.get(),
            }
            server_hello_data = pickle.dumps(server_hello)
            conn.send(server_hello_data)
            self.handshake_messages.append(server_hello_data)
            self.log(
                f'Sent ServerHello: Cipher={server_hello["cipher"]}, Client Auth Required={server_hello["client_auth_required"]}'
            )

            # Если требуется аутентификация клиента, ожидаем его сертификат
            if self.client_auth_var.get():
                client_cert_data = conn.recv(1024)
                if not client_cert_data:
                    self.log('Client did not send certificate')
                    conn.close()
                    return
                    
                client_cert = pickle.loads(client_cert_data)
                self.handshake_messages.append(client_cert_data)
                
                # Проверка подписи клиентского сертификата
                client_cert_obj = client_cert['certificate']
                client_signature = client_cert['signature']
                client_pub_key = RSA.import_key(client_cert_obj['public_key'])
                
                # Проверяем тип сертификата
                if client_cert_obj.get('type') != 'CLIENT':
                    self.log('Invalid client certificate type')
                    raise ValueError('Invalid client certificate type')
                
                h_cert = SHA256.new(pickle.dumps(client_cert_obj))
                try:
                    pkcs1_15.new(client_pub_key).verify(h_cert, client_signature)
                    self.log('Client certificate verified (self-signed)')
                except (ValueError, TypeError):
                    self.log('Client certificate verification failed')
                    raise ValueError('Invalid client certificate')
                
                # Клиент также должен подписать все предыдущие сообщения рукопожатия
                signature = conn.recv(256)
                if not signature:
                    self.log('Client did not send handshake signature')
                    conn.close()
                    return
                    
                h = SHA256.new(b''.join(self.handshake_messages))
                try:
                    pkcs1_15.new(client_pub_key).verify(h, signature)
                    self.log('Client handshake signature verified')
                except (ValueError, TypeError):
                    self.log('Client handshake signature verification failed')
                    raise ValueError('Invalid handshake signature')
                self.handshake_messages.append(signature)

            # Получение зашифрованных сессионных ключей
            encrypted_keys = conn.recv(1024)
            if not encrypted_keys:
                self.log('Client did not send encrypted keys')
                conn.close()
                return
                
            decrypted_keys = self.rsa_cipher.decrypt(encrypted_keys)
            self.aes_key = decrypted_keys[:32]
            self.mac_key = decrypted_keys[32:64]
            self.handshake_messages.append(encrypted_keys)
            self.log('Received and decrypted AES and MAC keys')

            # Отправка Server Finished
            finished_hash = SHA256.new(b''.join(self.handshake_messages)).digest()
            conn.send(finished_hash)
            self.log(f'Sent Server Finished message: {finished_hash.hex()}')

            # Получение Client Finished
            client_finished = conn.recv(32)
            expected_hash = SHA256.new(b''.join(self.handshake_messages)).digest()
            if client_finished != expected_hash:
                self.log('Client Finished verification failed')
                raise ValueError('Invalid Client Finished message')
            self.log('Received and verified Client Finished')

            conn.send(b'Handshake Complete')
            self.log('Handshake completed')

            # Начало обмена данными
            while self.server_running:
                data = conn.recv(1024)
                if not data:
                    self.log(f'Client {addr} disconnected')
                    break
                message = self.decrypt_message(data)
                self.log(f'Received (encrypted): {data.hex()}')
                self.log(f'Decrypted: {message}')
                response = f'Server response to {message}'
                encrypted_response = self.encrypt_message(response)
                conn.send(encrypted_response)
                self.log(f'Sent (encrypted): {encrypted_response.hex()}')
        except Exception as e:
            self.log(f'Error handling client {addr}: {e}')
        finally:
            conn.close()

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

    def send_message(self):
        if not self.client_threads or not self.ssl_sock or not self.aes_key:
            messagebox.showerror('Error', 'No active client connection or session key')
            return
        message = self.message_entry.get()
        if message:
            try:
                encrypted_message = self.encrypt_message(message)
                self.ssl_sock.send(encrypted_message)
                self.log(f'Sent (encrypted): {encrypted_message.hex()}')
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                self.log(f'Error sending: {e}')
                messagebox.showerror('Error', f'Send error: {e}')

    def stop_server(self):
        if not self.server_running:
            messagebox.showinfo('Info', 'Server is not running')
            return
        self.server_running = False
        if self.server_socket:
            self.server_socket.close()
        self.log('Server stopped')
        self.client_threads.clear()

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

    def exit(self):
        self.stop_server()
        self.window.quit()


if __name__ == '__main__':
    ServerGUI()