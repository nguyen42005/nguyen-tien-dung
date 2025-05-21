from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def encrypt(key, filename):
    key = SHA256.new(key.encode('utf-8')).digest()
    chunk_size = 64 * 1024
    output_file = os.path.join(UPLOAD_FOLDER, "encrypted_" + os.path.basename(filename))
    iv = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CFB, iv)
    
    with open(filename, 'rb') as infile:
        with open(output_file, 'wb') as outfile:
            outfile.write(iv)
            while chunk := infile.read(chunk_size):
                outfile.write(encryptor.encrypt(chunk))
    
    return output_file

def decrypt(key, filename):
    key = SHA256.new(key.encode('utf-8')).digest()
    chunk_size = 64 * 1024
    output_file = os.path.join(UPLOAD_FOLDER, "decrypted_" + os.path.basename(filename))
    
    with open(filename, 'rb') as infile:
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CFB, iv)
        
        with open(output_file, 'wb') as outfile:
            while chunk := infile.read(chunk_size):
                outfile.write(decryptor.decrypt(chunk))
    
    return output_file

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        key = request.form['key']
        action = request.form['action']
        
        if file and key:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            
            if action == 'encrypt':
                result_file = encrypt(key, filepath)
            elif action == 'decrypt':
                result_file = decrypt(key, filepath)
            else:
                return "Invalid action"
            
            return send_file(result_file, as_attachment=True)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
