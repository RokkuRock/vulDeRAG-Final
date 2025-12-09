# ✅ Few-Shot Baseline: Raw Model + Static Reasoning Examples
# ❌ Removed: RAG (ChromaDB), Dynamic Retrieval, CWE Crawler
# ✅ Preserved: Hardcoded Few-Shot Chain-of-Thought Examples, Interactive Snippet Mode

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

class FewShotRawPipeline:
    def __init__(self, model_path="./deepseek-coder-6.7b-instruct"):
        self.model_path = model_path
        self.llm = None

    def build_few_shot_prompt(self, full_code, vulnerable_snippet=None):
        """
        Constructs a prompt that includes STATIC Few-Shot examples (Chain-of-Thought)
        but excludes any RAG-retrieved content.
        """
        
        # 1. Define the Few-Shot Reasoning Examples (Hardcoded from original)
        few_shot_examples = """
[Example Reasoning 1]
Q1: The vulnerability type is Buffer Overflow because it was found that array operations lack boundary checks.
Q2: It appears in the strcpy call within the process_input function.
Q3: Attackers can exploit this vulnerability to execute arbitrary code.
Q4: It is recommended to use strncpy or other boundary-safe APIs.
Q5:
```
Corrected code omitted...
```
Q6: The key change is replacing strcpy with strncpy and adding length checks.

[Example Reasoning 2]
Q1: Insufficient Data Validation (CWE-20), because file operations are performed on unverified user input.
Q2: The issue appears where fopen uses an unverified path.
Q3: Attackers can open arbitrary files, causing information leakage.
Q4: Add input validation or use a whitelist.
Q5:
```
Corrected code omitted...
```
Q6: Added logic to check input format and a path whitelist.
"""

        # 2. Handle Focused Snippet Context
        target_context = ""
        if vulnerable_snippet:
            target_context = f"""
=== Focused Snippet (Suspected Vulnerability) ===
```
{vulnerable_snippet.strip()}
```
"""

        # 3. Construct the Final Prompt
        prompt = f"""
You are an expert familiar with security vulnerability repair in all programming languages.
Please refer to the following reasoning method (Few-Shot Examples) and provide repair suggestions for the target code based on your internal knowledge.

=== Full Code Context ===
```
{full_code[:2500]}
```
{target_context}

=== Reasoning Examples (How you should think) ===
{few_shot_examples}

=== Please analyze and repair the target code based on the above logic ===

Q1: What type of vulnerability might exist in the code? Please explain the basis.
Q2: Where exactly does the vulnerability appear in the code?
Q3: What kind of security risk might this vulnerability cause?
Q4: What is the recommended repair strategy?
Q5: Please provide the complete corrected code.
```
[Please output the complete compilable C code here, including corrected snippets and necessary logic]
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
            
            # Load model in float16
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
        print("🔐 Program starting (Few-Shot + Raw Model)...")
        print(f"📋 Parsing results: input={args.input}, snippet={args.snippet}, model_path={args.model_path}")
        print("🔐 Few-Shot Vulnerability Repair System (No RAG)")
        print("="*60)

        if args.input:
            if not Path(args.input).exists():
                print(f"❌ Error: File does not exist - {args.input}")
                return
            
            if not self.initialize():
                return

            full_code = self.read_code_file(args.input)
            
            prompt = ""
            if args.snippet:
                # Interactive snippet mode
                snippet = self.get_vulnerable_snippet_input()
                if snippet:
                    prompt = self.build_few_shot_prompt(full_code, vulnerable_snippet=snippet)
            else:
                # Full file analysis mode
                prompt = self.build_few_shot_prompt(full_code)

            if prompt:
                print("\n🧠 Model is analyzing (Few-Shot)...")
                result = self.llm.invoke(prompt)
                print("\n🔧 Analysis Result:\n", result)
        else:
            print("❌ Error: Please provide an input file using -i")

def main():
    parser = argparse.ArgumentParser(description="Few-Shot Vulnerability Repair (No RAG)")
    parser.add_argument('-i', '--input', type=str, help='Specify the code file to analyze')
    parser.add_argument('-s', '--snippet', action='store_true', help='Enable vulnerable snippet mode')
    parser.add_argument('--model-path', type=str, default="./DeepSeek-R1-Distill-Llama-8B")
    
    args = parser.parse_args()
    pipeline = FewShotRawPipeline(model_path=args.model_path)
    pipeline.run(args)

if __name__ == '__main__':
    main()