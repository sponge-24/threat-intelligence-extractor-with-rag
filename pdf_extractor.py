import pymupdf4llm
from langchain.text_splitter import MarkdownTextSplitter
from langchain_core.documents import Document

def extract_markdown_from_pdf(pdf_path):
    md_text = pymupdf4llm.to_markdown(
        doc=pdf_path,
        write_images=True,
        image_path="images",
        image_format="jpg",
        dpi=300,
    )
    return md_text


def convert_markdown_to_documents(md_text):
    splitter = MarkdownTextSplitter(chunk_size=500, chunk_overlap=100, keep_separator=True)
    split_docs = splitter.create_documents([md_text])
    documents = [
        Document(page_content=doc.page_content)
        for doc in split_docs
    ]
    return documents

# pdf_path = "threat_reports/Cisco_Iranian-MuddyWater-regionally-focused-subgroups(03-10-2022).pdf"
# md_text = extract_markdown_from_pdf(pdf_path)
# documents = convert_markdown_to_documents(md_text)
# print(md_text)