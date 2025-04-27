import re
import json
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_community.chat_models import ChatOllama
from langchain.memory import ConversationBufferMemory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableParallel
import shutil
import os

# Keep original QUERIES unchanged for compatibility
QUERIES = {
    "threat_actors": "Threat Actors, Attackers, APT Groups",
    "ttps": "Attacks, Tactics, Techniques, and Procedures (TTPs), Attack Patterns, Exploitation Techniques",
    "malware": "Malware, Malicious Files, Ransomware, Trojans, Worms, Keyloggers, Botnets, Fileless Malware, Rootkits, Backdoors",
    "targeted_entities": "Targeted Entities (victims), Industries, Organizations, Government Agencies, Geographic Regions"
}

# Modernize prompts while keeping same output format
PROMPTS = {
    "threat_actors": ChatPromptTemplate.from_messages([
        ("system", """You are a cybersecurity threat intelligence assistant. Extract structured threat intelligence data from the given report.

        **Rules:**
        - Only extract the name(s) of threat actors mentioned in the text.
        - Do **not** include any other JSON keys or additional data.

        **Strict JSON Response Format:**  
        {{
            "threat_actors": ["<Threat Actor Name>", "<Threat Actor Name>"]
        }}

        **Important:**  
        - If no threat actor is found, return an empty list (e.g., `"threat_actors": []`).
        - Do **not** use markdown or explanations, **only return JSON**."""),
        ("user", "{text}")
    ]),
    "ttps": ChatPromptTemplate.from_messages([
        ("system", """You are a cybersecurity threat intelligence assistant. Extract structured threat intelligence data from the given report.

        **Rules:**
        - Analyse and find the MITRE ATT&CK **Tactics and Techniques**.
        - Do **not** include any other JSON keys or additional data.

        **Strict JSON Response Format:**  
        {{
            "ttps": {{
                "Tactics": [
                    ["<Tactic Name>"],
                    ["<Tactic Name>"]
                ],
                "Techniques": [
                    ["<Technique Name>"],
                    ["<Technique Name>"]
                ]
            }}
        }}

        **Important:**  
        - If no TTPs are found, return an empty `"ttps": {{"Tactics": [], "Techniques": []}}` object.
        - Do **not** use markdown or explanations, **only return JSON**."""),
        ("user", "{text}")
    ]),
    "malware": ChatPromptTemplate.from_messages([
        ("system", """You are a cybersecurity threat intelligence assistant. Extract structured threat intelligence data from the given report.

        **Rules:**
        - Only extract the malware names.
        - Do **not** include any other JSON keys or additional data.

        **Strict JSON Response Format:**  
        {{
            "malware": [ 
                {{"Name": "<Malware Name>"}}
            ]
        }}

        **Important:**  
        - If no malware is found, return an empty list (e.g., `"malware": []`).
        - Do **not** use markdown or explanations, **only return JSON**."""),
        ("user", "{text}")
    ]),
    "targeted_entities": ChatPromptTemplate.from_messages([
        ("system", """Extract the names of **Targeted Entities** (industries, sectors, organizations) from the text.

        **Rules:**
        - Only extract the names of targeted industries/sectors.
        - Do **not** include any other JSON keys or additional data.

        **Strict JSON Response Format:**  
        {{
            "targeted_entities": ["<Entity Name>", "<Entity Name>"]
        }}

        **Important:**  
        - If no targeted entities are found, return an empty list (e.g., `"targeted_entities": []`).
        - Do **not** use markdown or explanations, **only return JSON**."""),
        ("user", "{text}")
    ]),
}

class RAGPipeline:
    def __init__(self):
        """Initialize the RAG pipeline with documents."""
        self.embeddings = HuggingFaceEmbeddings(model_name="all-mpnet-base-v2")
        self.persist_directory = "chroma_db"
        self.vectorstore = None
        self.retriever = None
        self.llm = ChatOllama(model="qwen2.5", num_ctx=4096)
        
        # Initialize memory
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        
        # Initialize chat prompt
        self.chat_prompt = ChatPromptTemplate.from_messages([
            ("system", "Use the following pieces of context to answer the question at the end. If you don't know the answer, just say that you don't know, don't try to make up an answer."),
            ("system", "Context: {context}"),
            MessagesPlaceholder(variable_name="chat_history"),
            ("user", "{question}")
        ])

        # Initialize the RAG chain
        self.rag_chain = None

    def _reset_vectorstore(self):
        """Clear the existing vector store data."""

        if os.path.exists(self.persist_directory):
            shutil.rmtree(self.persist_directory)

    def create_documents(self, documents):
        self._reset_vectorstore()
        self.vectorstore = Chroma.from_documents(
            documents, 
            self.embeddings,
            persist_directory=self.persist_directory
        )
        self.retriever = self.vectorstore.as_retriever(search_type="similarity", search_kwargs={"k": 15})
        # Setup RAG chain
        self.rag_chain = (
            RunnableParallel({
                "context": lambda x: self.retriever.get_relevant_documents(x["question"]),
                "question": lambda x: x["question"],
                "chat_history": lambda x: self.memory.load_memory_variables({})["chat_history"]
            })
            | {
                "answer": self.chat_prompt | self.llm | StrOutputParser(),
                "context": lambda x: x["context"]
            }
        )
    
    def generate_threat_intelligence(self):
        """Generate structured threat intelligence from the report."""
        extracted_data = []

        for key, query in QUERIES.items():

            retrieved_docs = self.retriever.get_relevant_documents(query)
            retrieved_text = " ".join([doc.page_content for doc in retrieved_docs])

            chain = (
                PROMPTS[key] 
                | self.llm 
                | StrOutputParser()
            )
            
            response = chain.invoke({"text": retrieved_text})
            
            # Clean JSON response
            result = re.sub(r'^\s*```(?:python|json)?\s*|\s*```$', '', response, flags=re.MULTILINE).strip()

            try:
                extracted_data.append(json.loads(result))
            except json.JSONDecodeError:
                extracted_data.append({"error": "Invalid JSON response"})

        return extracted_data
    
    def chat(self, question):
        """Process a chat question and return the response."""
        try:
            if not self.rag_chain:
                return "Please load documents first using create_documents()"
                
            result = self.rag_chain.invoke({"question": question})

            self.memory.save_context(
                {"input": question},
                {"output": result["answer"]}
            )
            
            return result["answer"]
            
        except Exception as e:
            return f"Error processing question: {str(e)}"