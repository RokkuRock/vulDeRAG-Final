# ✅ 完整回補版程式碼（file_with_vul_snippet-pure_chain-of-thought-pipeline.py）
# ✅ 已修正 END 輸入行為、保留完整 snippet 模式功能、上下文整合與互動分析流程

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

from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, pipeline
from peft import PeftModel
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
        summary = "請參考以下 CWE 弱點類型進行修復判斷：\n"
        for i, ex in enumerate(examples, 1):
            cwe = ex.metadata.get("cwe_id", "CWE-???")
            title = ex.metadata.get("example_title", "Unknown Example")
            summary += f"{i}. {cwe} - {title}\n"
        return summary.strip()

    def build_focused_repair_prompt(self, full_code, vulnerable_snippet, similar_examples):
        cwe_summary = self.summarize_similar_cwe_types(similar_examples)
        prompt = f"""
你是一位熟悉所有程式語言安全漏洞修復的專家。
請根據下方資訊進行完整修復建議：

=== CWE 弱點摘要 ===
{cwe_summary}

=== 完整程式碼上下文 ===
```
{full_code[:1800]}{'...(truncated)' if len(full_code) > 1800 else ''}
```

=== 聚焦片段 (懷疑有漏洞) ===
```
{vulnerable_snippet.strip()}
```

=== 向量資料庫中的 CWE 相似範例 ===
"""
        for i, example in enumerate(similar_examples, 1):
            cwe_id = example.metadata.get('cwe_id', 'Unknown')
            title = example.metadata.get('example_title', 'Unknown')
            code = example.metadata.get('original_snippet', '').strip()
            prompt += f"""
[範例 {i}] {cwe_id} - {title}
```
{code[:500]}...
```
"""
        prompt += f"""
請根據上方資訊回答以下問題：

Q1: 程式碼可能存在什麼類型的漏洞？請說明依據。
Q2: 漏洞具體出現在程式碼的哪個位置？
Q3: 這個漏洞可能造成什麼樣的安全風險？
Q4: 建議的修復策略是什麼？
Q5: 請提供修復後的完整程式碼。
```
[請在此輸出完整可編譯的 C 程式碼，需包含修正片段與必要邏輯]
```
Q6: 修復的關鍵變更有哪些？
"""
        return prompt

    def get_vulnerable_snippet_input(self):
        print("\n請輸入需要聚焦分析的程式碼片段，輸入 END 結束：")
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

        bnb_config = BitsAndBytesConfig(load_in_8bit=True)

        base_model = AutoModelForCausalLM.from_pretrained(
            "DeepSeek-R1-Distill-Llama-8B",
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.float16
        )

        model = PeftModel.from_pretrained(base_model, self.model_path)
        tokenizer = AutoTokenizer.from_pretrained(self.model_path, use_fast=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        pipe = pipeline("text-generation", model=model, tokenizer=tokenizer, max_new_tokens=2048, temperature=0.1, top_p=0.9)
        self.llm = HuggingFacePipeline(pipeline=pipe)
        print("✅ System initialization completed!")
        return True

    def run(self, args):
        print("🔐 程式開始執行...")
        print(f"📋 解析結果: input={args.input}, snippet={args.snippet}, model_path={args.model_path}")
        print("🔐 整合式 RAG 漏洞修復系統 (簡化版)")
        print("="*60)

        if args.input:
            if not Path(args.input).exists():
                print(f"❌ 錯誤: 文件不存在 - {args.input}")
                return
            if not self.initialize(force_rebuild_db=args.rebuild, force_recollect_cwe=args.recollect):
                print("❌ 系統初始化失敗")
                return
            full_code = self.read_code_file(args.input)
            if args.snippet:
                snippet = self.get_vulnerable_snippet_input()
                if snippet:
                    similar = self.find_similar_vulnerabilities(snippet)
                    prompt = self.build_focused_repair_prompt(full_code, snippet, similar)
                    result = self.llm.invoke(prompt)
                    print("\n🔧 分析結果:\n", result)
            else:
                similar = self.find_similar_vulnerabilities(full_code)
                prompt = self.build_focused_repair_prompt(full_code, full_code, similar)
                result = self.llm.invoke(prompt)
                print("\n🔧 分析結果:\n", result)

# ✅ 主程式入口

def main():
    parser = argparse.ArgumentParser(description="RAG 漏洞修復系統")
    parser.add_argument('-i', '--input', type=str, help='指定要分析的程式碼文件')
    parser.add_argument('-s', '--snippet', action='store_true', help='啟用 vulnerable snippet 模式')
    parser.add_argument('--model-path', type=str, default="./DeepSeek-R1-Distill-Llama-8B")
    parser.add_argument('--db-dir', type=str, default="./chroma_db")
    parser.add_argument('--rebuild', action='store_true')
    parser.add_argument('--recollect', action='store_true')
    args = parser.parse_args()
    pipeline = IntegratedRAGPipeline(model_path=args.model_path, db_dir=args.db_dir)
    pipeline.run(args)

if __name__ == '__main__':
    main()
