# ✅ Complete restored version code (file_with_vul_snippet-pure_chain-of-thought-pipeline.py)
# ✅ Fixed END input behavior, preserved complete snippet mode functionality, context integration, and interactive analysis flow

import json
import re
from pathlib import Path
from langchain_core.documents import Document
from typing import List
import argparse
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from langchain_huggingface import HuggingFaceEmbeddings, HuggingFacePipeline
    from langchain_chroma import Chroma
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_community.vectorstores import Chroma
    from langchain_community.llms import HuggingFacePipeline

from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch
from new_cwe_crawler import CWECollector

class IntegratedRAGPipeline:
    def __init__(self, model_path="./DeepSeek-R1-Distill-Llama-8B", db_dir="./chroma_db"):
        self.model_path = model_path
        self.db_dir = db_dir
        self.vectordb = None
        self.llm = None
        self.cwe_collector = CWECollector(delay=1)

    def summarize_similar_cwe_types(self, examples):
        summary = "Please refer to the following CWE vulnerability types for repair judgment:\n"
        for i, ex in enumerate(examples, 1):
            cwe = ex.metadata.get("cwe_id", "CWE-???")
            title = ex.metadata.get("example_title", "Unknown Example")
            summary += f"{i}. {cwe} - {title}\n"
        return summary.strip()

    def build_focused_repair_prompt(self, full_code, vulnerable_snippet, similar_examples):
        cwe_summary = self.summarize_similar_cwe_types(similar_examples)
        prompt = f"""
You are an expert familiar with security vulnerability repair in all programming languages.
Please make complete repair suggestions based on the information below:

=== CWE Vulnerability Summary ===
{cwe_summary}

=== Full Code Context ===
```
{full_code[:1800]}{'...(truncated)' if len(full_code) > 1800 else ''}
```

=== Focused Snippet (Suspected Vulnerability) ===
```
{vulnerable_snippet.strip()}
```

=== Similar CWE Examples from Vector Database ===
"""
        for i, example in enumerate(similar_examples, 1):
            cwe_id = example.metadata.get('cwe_id', 'Unknown')
            title = example.metadata.get('example_title', 'Unknown')
            code = example.metadata.get('original_snippet', '').strip()
            prompt += f"""
[Example {i}] {cwe_id} - {title}
```
{code[:500]}...
```
"""
        prompt += f"""
Please answer the following questions based on the information above:

Q1: What type of vulnerability might exist in the code? Please explain the basis.
Q2: Where exactly does the vulnerability appear in the code?
Q3: What kind of security risk might this vulnerability cause?
Q4: What is the recommended repair strategy?
Q5: Please provide the complete corrected code.
```
[Please output the complete compilable or directly executable code here, including corrected snippets and necessary logic]
```
Q6: What are the key changes in the repair?
"""
        return prompt

    def get_vulnerable_snippet_input(self):
        print("\nPlease enter the code snippet for focused analysis, type END to finish:")
        snippet_lines = []
        while True:
            try:
                line = input()
                if line.strip() == 'END':
                    break
                snippet_lines.append(line)
            except EOFError:
                break
        print("\n✅ Vulnerable snippet input received, model inferencing...")
        return '\n'.join(snippet_lines)


    def read_code_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()

    def find_similar_vulnerabilities(self, code, k=3):
        return self.vectordb.as_retriever(search_kwargs={"k": k}).invoke(code)

    def initialize(self, force_rebuild_db=False, force_recollect_cwe=False):
        embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        self.vectordb = Chroma(persist_directory=self.db_dir, embedding_function=embedding_model)
        tokenizer = AutoTokenizer.from_pretrained(self.model_path, use_fast=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(self.model_path, device_map="auto", torch_dtype=torch.float16)
        pipe = pipeline("text-generation", model=model, tokenizer=tokenizer, max_new_tokens=2048, temperature=0.1, top_p=0.9)
        self.llm = HuggingFacePipeline(pipeline=pipe)
        print("✅ System initialization completed!")
        return True

    def run(self, args):
        print("\U0001f512 Program starting...")
        print(f"\U0001f4cb Parsing results: input={args.input}, snippet={args.snippet}, model_path={args.model_path}")
        print("\U0001f512 Integrated RAG Vulnerability Repair System (Simplified Version)")
        print("="*60)

        if args.input:
            if not Path(args.input).exists():
                print(f"❌ Error: File does not exist - {args.input}")
                return
            if not self.initialize(force_rebuild_db=args.rebuild, force_recollect_cwe=args.recollect):
                print("❌ System initialization failed")
                return
            full_code = self.read_code_file(args.input)
            if args.snippet:
                snippet = self.get_vulnerable_snippet_input()
                if snippet:
                    similar = self.find_similar_vulnerabilities(snippet)
                    prompt = self.build_focused_repair_prompt(full_code, snippet, similar)
                    result = self.llm.invoke(prompt)
                    print("\n🔧 Analysis Result:\n", result)
            else:
                similar = self.find_similar_vulnerabilities(full_code)
                prompt = self.build_focused_repair_prompt(full_code, full_code, similar)
                result = self.llm.invoke(prompt)
                print("\n🔧 Analysis Result:\n", result)

# ✅ Main Program Entry

def main():
    parser = argparse.ArgumentParser(description="RAG Vulnerability Repair System")
    parser.add_argument('-i', '--input', type=str, help='Specify the code file to analyze')
    parser.add_argument('-s', '--snippet', action='store_true', help='Enable vulnerable snippet mode')
    parser.add_argument('--model-path', type=str, default="./DeepSeek-R1-Distill-Llama-8B")
    parser.add_argument('--db-dir', type=str, default="./chroma_db")
    parser.add_argument('--rebuild', action='store_true')
    parser.add_argument('--recollect', action='store_true')
    args = parser.parse_args()
    pipeline = IntegratedRAGPipeline(model_path=args.model_path, db_dir=args.db_dir)
    pipeline.run(args)

if __name__ == '__main__':
    main()