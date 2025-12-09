# ✅ Baseline Control Group: Raw Model Inference Only
# ❌ Removed: RAG (ChromaDB), Few-Shot Examples, CWE Crawler dependencies
# ✅ Preserved: Interactive Snippet Mode, Full Context Handling

import argparse
import torch
from pathlib import Path
import warnings

# Filter warnings for cleaner output
warnings.filterwarnings("ignore")

try:
    from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
    from langchain_huggingface import HuggingFacePipeline
except ImportError:
    print("❌ Error: Missing required libraries. Please install transformers and langchain_huggingface.")
    exit(1)

class BaselineRepairPipeline:
    def __init__(self, model_path="./deepseek-coder-6.7b-instruct"):
        self.model_path = model_path
        self.llm = None

    def build_baseline_prompt(self, full_code, vulnerable_snippet=None):
        """
        Constructs a Zero-Shot prompt without RAG or Few-Shot examples.
        Relies purely on the model's pre-trained knowledge.
        """
        
        # If a specific snippet is provided, we highlight it; otherwise, we focus on the full code.
        target_context = ""
        if vulnerable_snippet:
            target_context = f"""
=== Focused Snippet (Suspected Vulnerability) ===
```
{vulnerable_snippet.strip()}
```
"""

        prompt = f"""
You are an expert familiar with security vulnerability repair in all programming languages.
Please analyze the code provided below and suggest repairs based solely on your security knowledge.

=== Full Code Context ===
```
{full_code[:2500]}
```
{target_context}

Please answer the following questions clearly:

Q1: What type of vulnerability might exist in the code?
Q2: Where exactly does the vulnerability appear in the code?
Q3: What kind of security risk might this vulnerability cause?
Q4: What is the recommended repair strategy?
Q5: Please provide the complete corrected code.
```
[Please output the complete compilable C code here]
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

    def initialize(self):
        print(f"⏳ Loading model from: {self.model_path} ...")
        
        try:
            tokenizer = AutoTokenizer.from_pretrained(self.model_path, use_fast=True)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            # Load model in standard float16 (adjust device_map as needed)
            model = AutoModelForCausalLM.from_pretrained(
                self.model_path, 
                device_map="auto", 
                torch_dtype=torch.float16
            )
            
            pipe = pipeline(
                "text-generation", 
                model=model, 
                tokenizer=tokenizer, 
                max_new_tokens=2048, 
                temperature=0.1, 
                top_p=0.9
            )
            self.llm = HuggingFacePipeline(pipeline=pipe)
            print("✅ Model initialization completed!")
            return True
        except Exception as e:
            print(f"❌ Model initialization failed: {e}")
            return False

    def run(self, args):
        print("🔐 Program starting (Baseline Control Group)...")
        print(f"📋 Parsing results: input={args.input}, snippet={args.snippet}, model_path={args.model_path}")
        print("🔐 Baseline Vulnerability Repair System (Raw Model Only)")
        print("="*60)

        if args.input:
            if not Path(args.input).exists():
                print(f"❌ Error: File does not exist - {args.input}")
                return
            
            # Initialize Model Only (No DB)
            if not self.initialize():
                return

            full_code = self.read_code_file(args.input)
            
            prompt = ""
            if args.snippet:
                # Interactive snippet mode
                snippet = self.get_vulnerable_snippet_input()
                if snippet:
                    prompt = self.build_baseline_prompt(full_code, vulnerable_snippet=snippet)
            else:
                # Full file analysis mode
                prompt = self.build_baseline_prompt(full_code)

            if prompt:
                print("\n🧠 Model is analyzing (Zero-Shot)...")
                # Invoke the model directly
                result = self.llm.invoke(prompt)
                print("\n🔧 Analysis Result:\n", result)
        else:
            print("❌ Error: Please provide an input file using -i")

def main():
    parser = argparse.ArgumentParser(description="Baseline Vulnerability Repair (No RAG/Few-Shot)")
    parser.add_argument('-i', '--input', type=str, help='Specify the code file to analyze')
    parser.add_argument('-s', '--snippet', action='store_true', help='Enable vulnerable snippet mode')
    parser.add_argument('--model-path', type=str, default="./DeepSeek-R1-Distill-Llama-8B")
    
    # Removed --db-dir, --rebuild, --recollect arguments as they are not needed for baseline
    
    args = parser.parse_args()
    pipeline = BaselineRepairPipeline(model_path=args.model_path)
    pipeline.run(args)

if __name__ == '__main__':
    main()