from flask import Flask, send_file
import os

app = Flask(__name__)
app.secret_key = 'secret_discret'
SAVE_PATH = './audio/'

@app.route('/upload', methods=['POST'])
def upload_file():
    from flask import request, redirect, url_for
    from werkzeug.utils import secure_filename
    import os

    UPLOAD_FOLDER = 'audio/'
    ALLOWED_EXTENSIONS = {'mp3', 'wav'}
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    file = request.files['file']
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)
    return {"message": "File uploaded successfully", "path": path}

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    path = os.path.join(SAVE_PATH, filename)
    
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return {"error": "File not found"}, 404
    
    return send_file(path, as_attachment=True, mimetype='audio/mpeg', download_name=filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=2000)