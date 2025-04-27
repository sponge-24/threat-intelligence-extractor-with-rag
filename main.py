from flask import Flask, render_template, request, jsonify, send_from_directory, session
import os
from werkzeug.utils import secure_filename
import json
from pdf_extractor import extract_markdown_from_pdf, convert_markdown_to_documents
from ioc_extractor import extract_iocs_from_pdf
from hash_analysis import analyze_hashes
from rag_pipeline import RAGPipeline
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['IMAGE_FOLDER'] = 'images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'pdf'}
virus_total_api_key = os.getenv('virus_total_api_key')
rag_pipeline = None

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_pdf(filepath):
    try:
        # Extract elements and convert to documents
        markdown_text = extract_markdown_from_pdf(filepath)
        documents = convert_markdown_to_documents(markdown_text)
        
        # Extract IoCs
        threat_intelligence = extract_iocs_from_pdf(markdown_text)
        
        # Run RAG pipeline
        global rag_pipeline

        rag_pipeline = RAGPipeline()
        rag_pipeline.create_documents(documents) 
        additional_intel = rag_pipeline.generate_threat_intelligence()
        
        # Combine results
        threat_intelligence.extend(additional_intel)

        return threat_intelligence
    except Exception as e:
        raise Exception(f"Error processing PDF: {str(e)}")

def clear_images_folder():
    """Clear all files from the images folder"""
    if os.path.exists('images'):
        for filename in os.listdir('images'):
            file_path = os.path.join('images', filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only PDF files are allowed'}), 400
        
        clear_images_folder()
        
        # Save file securely
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(filepath)
            
            # Process the PDF
            threat_intelligence = process_pdf(filepath)
            
            # Store results in session
            session['threat_intelligence'] = json.dumps(threat_intelligence)
            
            return jsonify({
                'success': True,
                'message': 'File processed successfully',
                'data': threat_intelligence
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
            
        finally:
            # Clean up uploaded file
            if os.path.exists(filepath):
                os.remove(filepath)
                
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/get_intelligence', methods=['POST'])
def get_intelligence():
    try:
        selected_types = request.json.get('types', [])
        threat_intelligence = json.loads(session.get('threat_intelligence', '[]'))
        
        if not threat_intelligence:
            return jsonify({'error': 'No threat intelligence data found'}), 404
            
        filtered_data = {}

        if 'iocs' in selected_types and threat_intelligence:
            filtered_data.update(threat_intelligence[0]) 

        for item in threat_intelligence:  
            item_type = list(item.keys())[0]
            if item_type in selected_types:
                filtered_data.update(item)
        
        return jsonify({'data': filtered_data})
        
    except Exception as e:
        return jsonify({'error': f'Error retrieving intelligence: {str(e)}'}), 500


@app.route('/analyze_hashes', methods=['POST'])
def get_hash_analysis():
    try:
        threat_intelligence = json.loads(session.get('threat_intelligence', '[]'))
        
        if not threat_intelligence:
            return jsonify({'error': 'No threat intelligence data found'}), 404
            
        if not virus_total_api_key:
            return jsonify({'error': 'VirusTotal API key not configured'}), 500
            
        # Analyze hashes from the first item (IoCs)
        hash_analysis = analyze_hashes(threat_intelligence[0],api_key=virus_total_api_key)
        
        return jsonify({'data': hash_analysis})
        
    except Exception as e:
        return jsonify({'error': f'Error analyzing hashes: {str(e)}'}), 500

@app.route('/list_images')
def list_images():
    """List all images in the images directory"""
    try:
        images = []
        for filename in os.listdir(app.config['IMAGE_FOLDER']):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                images.append(filename)
        return jsonify({'images': images})
    except Exception as e:
        return jsonify({'error': f'Error listing images: {str(e)}'}), 500

@app.route('/images/<path:filename>')
def serve_image(filename):
    """Serve images from the image folder"""
    return send_from_directory(app.config['IMAGE_FOLDER'], filename)

@app.route('/chat_interface')
def chat_interface():
    """Render the chat interface."""
    return render_template('chat.html')

@app.route('/chat', methods=['POST'])
def chat():
    """Process chat messages and return responses."""
    try:
            
        message = request.json.get('message')
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Process the message and get response
        response = rag_pipeline.chat(message)
        
        return jsonify({'response': response})
        
    except Exception as e:
        return jsonify({'error': f'Error processing message: {str(e)}'}), 500
    
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)