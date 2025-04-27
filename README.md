# Threat Intelligence Extractor with RAG

A powerful web application for extracting and analyzing threat intelligence from PDF security reports using Retrieval Augmented Generation (RAG).

![Threat Intelligence Extractor](/outputs/output_1.JPG)
![Threat Intelligence Extractor](/outputs/output_2.JPG)

## Features

- **PDF Processing**: Extract text, structure, and images from security reports
- **IoC Extraction**: Automatically identify IoCs (Indicators of Compromise) from PDF content
- **AI-Enhanced Analysis**: Use RAG (Retrieval Augmented Generation) to generate additional threat intelligence
- **Hash Analysis**: Integration with VirusTotal API for malware hash verification
- **Interactive Chat**: Ask questions about the report content using a conversational interface
- **Visualizations**: View extracted images and diagrams from reports
- **Modern Cyberpunk UI**: Sleek, responsive design with a cybersecurity aesthetic

## Getting Started

### Prerequisites

- Python 3.8+
- Flask
- PyMuPDF
- Langchain
- Ollama (for local LLM support)
- VirusTotal API key (for hash analysis)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sponge-24/threat-intelligence-extractor-with-rag.git
   cd threat-intelligence-extractor-with-rag
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install Ollama (required for the local LLM):

   **For macOS/Linux:**
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

   **For Windows:**
   - Download the installer from [Ollama's official website](https://ollama.com/download)
   - Run the installer and follow the on-screen instructions

5. Download the Qwen model for use with Ollama:
   ```bash
   ollama pull qwen2.5
   ```

6. Set up environment variables by creating a `.env` file:
   ```
   virus_total_api_key=your_virustotal_api_key_here
   ```

### Running the Application

1. Make sure Ollama is running in the background:
   ```bash
   # Check if Ollama is running
   ollama ps
   
   # If not running, start the Ollama service
   # This usually happens automatically after installation
   ```

2. Start the application:
   ```bash
   python main.py
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

### Analyzing a Security Report

1. Click "SELECT PDF FILE" and choose a security report in PDF format
2. Click "PROCESS REPORT" to extract intelligence
3. Select intelligence types to view (IoCs, Threat Actors, TTPs, etc.)
4. Use "ANALYZE HASHES" to check file hashes against VirusTotal
5. Click "CHAT WITH PDF" to ask questions about the report

### Interacting with the Chat Interface

The chat interface allows you to ask questions about the uploaded PDF:
- Ask about specific threats mentioned
- Request summaries of attack techniques
- Get clarification on technical details
- Inquire about affected systems or organizations

## Architecture

The application consists of several key components:

- **PDF Extractor**: Converts PDFs to structured markdown with image extraction
- **IoC Extractor**: Identifies and categorizes Indicators of Compromise
- **RAG Pipeline**: Uses embeddings and an LLM to generate enhanced threat intelligence
- **Hash Analysis**: Verifies file hashes against VirusTotal's database
- **Web Interface**: Provides an interactive UI for data visualization and chat

## Technologies Used

- **Backend**: Flask, Python
- **PDF Processing**: PyMuPDF
- **NLP/ML**: Langchain, Hugging Face Embeddings, Ollama
- **Frontend**: HTML, CSS, JavaScript, Tailwind CSS
- **APIs**: VirusTotal

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- [Langchain](https://github.com/langchain-ai/langchain) for the RAG implementation
- [PyMuPDF](https://github.com/pymupdf/PyMuPDF) for PDF extraction
- [IOC Finder](https://github.com/fhightower/ioc-finder) for IoC extraction
- [Ollama](https://ollama.com/) for local LLM support