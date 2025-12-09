import json
import re
from pathlib import Path
from langchain_core.documents import Document

# Handle deprecation warnings
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

# Import CWE collector (crawler version)
from cwe_crawler import CWECollector, get_common_cwe_ids

class IntegratedRAGPipeline:
    """Integrated RAG Vulnerability Repair System - Using Llama 3.1 (Simplified)"""
    
    def __init__(self, model_path="./llama3.1", db_dir="./chroma_db"):
        self.model_path = model_path
        self.db_dir = db_dir
        self.vectordb = None
        self.llm = None
        self.cwe_collector = CWECollector(delay=1)
        self.cwe_examples_file = "cwe_examples.json"
    
    # === STEP 1: CWE Data Collection and Processing ===
    def collect_or_load_cwe_data(self, cwe_ids=None, use_cache=True, force_recollect=False):
        """Collect or load CWE vulnerability example data"""
        cache_path = Path(self.cwe_examples_file)
        
        # Check if forced recollection is needed
        if force_recollect and cache_path.exists():
            print(f"[INFO] Force recollection, deleting old cache file: {self.cwe_examples_file}")
            cache_path.unlink()
        
        # Check cache file
        if use_cache and cache_path.exists():
            print(f"[INFO] Loading CWE data from cache: {self.cwe_examples_file}")
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    # Check data format
                    if 'cwe_examples' in cached_data:
                        cwe_examples = cached_data['cwe_examples']
                    elif isinstance(cached_data, dict) and all(isinstance(k, (str, int)) for k in cached_data.keys()):
                        # Direct cwe_examples format
                        cwe_examples = cached_data
                    else:
                        print("[WARN] Cache file format incorrect, will recollect data")
                        cwe_examples = None
                    
                    if cwe_examples:
                        total_examples = sum(len(examples) for examples in cwe_examples.values())
                        print(f"[INFO] Successfully loaded {len(cwe_examples)} CWE types, total {total_examples} examples")
                        return cwe_examples
            except Exception as e:
                print(f"[WARN] Failed to load cache file: {e}")
        
        # Collect new data
        if cwe_ids is None:
            cwe_ids = get_common_cwe_ids()[:100]  # Limit quantity to avoid taking too long
        
        print(f"[INFO] Starting to collect example data for {len(cwe_ids)} CWEs via crawler...")
        print("=" * 50)
        
        cwe_examples = self.cwe_collector.collect_multiple_cwes(cwe_ids)
        
        if not cwe_examples:
            print("[ERROR] Unable to collect CWE data")
            return {}
        
        # Save as JSON format
        try:
            output_data = {
                "collection_info": {
                    "total_cwes": len(cwe_examples),
                    "total_examples": sum(len(examples) for examples in cwe_examples.values()),
                    "cwe_ids": list(cwe_examples.keys())
                },
                "cwe_examples": cwe_examples
            }
            
            with open(self.cwe_examples_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            total_examples = sum(len(examples) for examples in cwe_examples.values())
            print(f"[INFO] CWE data saved to: {self.cwe_examples_file}")
            print(f"[INFO] Successfully collected {len(cwe_examples)} CWE types, total {total_examples} examples")
            
        except Exception as e:
            print(f"[WARN] Error occurred while saving CWE data: {e}")
        
        return cwe_examples
    
    def cwe_to_documents(self, cwe_examples):
        """Convert CWE data to Document format"""
        documents = []
        
        for cwe_id, examples in cwe_examples.items():
            # Handle different formats of cwe_id (could be string or integer)
            cwe_id_str = str(cwe_id)
            
            for i, example in enumerate(examples):
                # Create rich metadata
                metadata = {
                    "cwe_id": f"CWE-{cwe_id_str}",
                    "vulnerability_type": f"CWE-{cwe_id_str}",
                    "example_title": example.get('title', f'Example {i+1}'),
                    "source": example.get('source', 'crawler'),
                    "file": f"cwe_{cwe_id_str}_example_{i+1}",
                    "bug_block_id": f"{cwe_id_str}_{i+1}",
                    "original_snippet": example.get('code', '')
                }
                
                # Content format optimized for vector search
                content = f"""Vulnerability Type: CWE-{cwe_id_str}
Example Title: {example.get('title', f'Example {i+1}')}
Code:
{example.get('code', '')}"""
                
                documents.append(Document(
                    page_content=content,
                    metadata=metadata
                ))
        
        print(f"[INFO] Conversion completed: {len(documents)} documents")
        return documents
    
    # === STEP 2: Vector Database Construction ===
    def build_or_load_vectordb(self, force_rebuild=False, force_recollect_cwe=False):
        """Build or load vector database"""
        db_path = Path(self.db_dir)
        
        if not force_rebuild and db_path.exists() and not force_recollect_cwe:
            print("[INFO] Loading existing vector database...")
            try:
                embedding_model = HuggingFaceEmbeddings(
                    model_name="sentence-transformers/all-MiniLM-L6-v2"
                )
                self.vectordb = Chroma(
                    persist_directory=self.db_dir,
                    embedding_function=embedding_model
                )
                print("[SUCCESS] Vector database loaded successfully!")
                return True
            except Exception as e:
                print(f"[WARN] Failed to load existing database: {e}")
                print("[INFO] Will rebuild database...")
        
        # Build new vector database
        print("[INFO] Building new vector database...")
        
        # Collect CWE data
        cwe_examples = self.collect_or_load_cwe_data(force_recollect=force_recollect_cwe)
        if not cwe_examples:
            print("[ERROR] Unable to collect or load CWE data")
            return False
        
        # Convert to documents
        documents = self.cwe_to_documents(cwe_examples)
        if not documents:
            print("[ERROR] Unable to create documents")
            return False
        
        # Create vector database
        try:
            # If database directory exists, delete it first
            if db_path.exists():
                import shutil
                shutil.rmtree(db_path)
                print("[INFO] Deleted old vector database")
            
            embedding_model = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2"
            )
            
            self.vectordb = Chroma.from_documents(
                documents=documents,
                embedding=embedding_model,
                persist_directory=self.db_dir
            )
            
            # Persist database
            try:
                self.vectordb.persist()
            except AttributeError:
                # New version of Chroma auto-persists
                pass
                
            print(f"[SUCCESS] Vector database construction completed! Contains {len(documents)} documents")
            return True
            
        except Exception as e:
            print(f"[ERROR] Vector database construction failed: {e}")
            return False
    
    # === STEP 3: Load Llama 3.1 Model ===
    def load_llm(self):
        """Load local Llama 3.1 model"""
        try:
            print("[INFO] Loading local Llama 3.1 model...")
            
            tokenizer = AutoTokenizer.from_pretrained(self.model_path, use_fast=True)
            
            # Set pad_token if not present
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True
            )
            
            pipe = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                max_new_tokens=2048,
                temperature=0.1,
                top_p=0.9,
                repetition_penalty=1.15,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id
            )
            
            self.llm = HuggingFacePipeline(pipeline=pipe)
            print("[SUCCESS] Llama 3.1 model loaded successfully!")
            return True
            
        except Exception as e:
            print(f"[ERROR] Model loading failed: {e}")
            return False
    
    # === STEP 4: Similarity Search ===
    def find_similar_vulnerabilities(self, user_code, k=3):
        """Search for similar vulnerability examples"""
        if not self.vectordb:
            print("[ERROR] Vector database not initialized")
            return []
        
        try:
            retriever = self.vectordb.as_retriever(search_kwargs={"k": k})
            similar_docs = retriever.invoke(user_code)
            return similar_docs
        except AttributeError:
            # Fallback to old API
            retriever = self.vectordb.as_retriever(search_kwargs={"k": k})
            similar_docs = retriever.get_relevant_documents(user_code)
            return similar_docs
    
    # === STEP 5: Build Repair Prompt ===
    def build_repair_prompt(self, user_code, similar_examples):
        """Build a strict and instructive prompt for code repair with fixed structure and reference"""
        
        prompt = (
            "You are a secure code repair assistant. Your job is to analyze the given vulnerable code, "
            "detect possible security flaws, and apply appropriate fixes. You MUST use the examples retrieved "
            "from the database (provided below) as your primary guidance.\n\n"

            "CRITICAL REQUIREMENTS:\n"
            "1. You MUST identify vulnerabilities based on the similar examples provided from the vector database\n"
            "2. You MUST provide complete, working fixed code with CORRECT SYNTAX\n"
            "3. You MUST ensure the fixed code compiles and runs without errors\n"
            "4. You MUST follow the exact output format specified below\n"
            "5. The fixed code must be syntactically correct and executable\n\n"

            "Do not mimic the following general fix unless it directly matches the pattern in the retrieved examples, "
            "this is just for telling you what you should do.\n\n"

            "## 🧪 General Example Fix (for reference only):\n"
            "This is **only one possible example** of a buffer overflow fix and **may not apply** to your task.\n\n"

            "### Before:\n"
            "```c\n"
            "#include <stdio.h>\n"
            "void hacker()\n"
            "{\n"
            "    printf(\"No, I'm a hacker!\\n\");\n"
            "}\n"
            "void nonSecure()\n"
            "{\n"
            "    char name[16];\n"
            "    printf(\"What's your name?\\n\");\n"
            "    gets(name);\n"
            "    printf(\"Hey %s, you're harmless, aren't you?\\n\", name);\n"
            "}\n"
            "int main()\n"
            "{\n"
            "    nonSecure();\n"
            "    return 0;\n"
            "}\n"
            "```\n\n"

            "### After:\n"
            "```c\n"
            "#include <stdio.h>\n"
            "void hacker()\n"
            "{\n"
            "    printf(\"No, I'm a hacker!\\n\");\n"
            "}\n"
            "void nonSecure()\n"
            "{\n"
            "    char name[16];\n"
            "    printf(\"What's your name?\\n\");\n"
            "    fgets(name, sizeof(name), stdin);\n"
            "    printf(\"Hey %s, you're harmless, aren't you?\\n\", name);\n"
            "}\n"
            "int main()\n"
            "{\n"
            "    nonSecure();\n"
            "    return 0;\n"
            "}\n"
            "```\n\n"
            "⚠️ Again: This is just one possible fix. You must rely on the retrieved CWE examples below for actual repair logic.\n\n"

            "🔒 Original Vulnerable Code:\n"
            "```java\n"
        )
        prompt += user_code + "\n```\n\n"

        if similar_examples:
            prompt += "## 📚 Retrieved Similar Vulnerability Examples (from vector DB):\n"
            for i, example in enumerate(similar_examples[:2], 1):
                cwe_id = example.metadata.get('cwe_id', 'Unknown')
                title = example.metadata.get('example_title', 'Example')
                example_code = example.page_content.split("Code:", 1)[-1].strip()
                prompt += f"\n### Example {i}: {cwe_id} - {title}\n"
                prompt += "```java\n" + example_code + "\n```\n"

        prompt += (
            "\n🛠️ Instructions:\n"
            "Identify the vulnerability type (e.g., CWE-89 for SQL Injection, CWE-120 for buffer overflow).\n"
            "Use the reference examples above to guide the fix.\n"
            "Do NOT base your fix on the general example unless it matches.\n"
            "You MUST output complete and corrected code (not partial snippets).\n"
            "Explain what was fixed and why.\n\n"

            "✅ Output Format (strictly follow this structure):\n"
            "Vulnerability: CWE-XXX - [Explanation]\n\n"
            "Fixed Code:\n"
            "```java\n"
            "// complete corrected Java code\n"
            "```\n\n"
            "Key Changes:\n"
            "Change 1: [explanation]\n"
            "Change 2: [explanation]\n\n"
            "Start your secure code repair analysis now:\n"
        )

        return prompt

    # === STEP 6: Output Processing ===
    def clean_model_output(self, raw_output, original_prompt):
        """Clean model output"""
        if original_prompt in raw_output:
            cleaned = raw_output.split(original_prompt)[-1].strip()
        else:
            cleaned = raw_output.strip()
        
        # Remove common conversation starters
        unwanted_starts = [
            "I'll analyze", "Let me analyze", "I need to analyze",
            "Based on the provided", "First,", "I'll help you", "As a professional",
            "I will analyze for you", "Let me help you analyze"
        ]
        
        for start in unwanted_starts:
            if cleaned.startswith(start):
                lines = cleaned.split('\n')
                for i, line in enumerate(lines):
                    if line.strip().startswith('#') or line.strip().startswith('##') or 'Vulnerability' in line:
                        cleaned = '\n'.join(lines[i:])
                        break
                break
        
        return cleaned
    
    # === STEP 7: Simplified Repair Process ===
    def repair_vulnerability(self, user_code):
        """Execute vulnerability repair - simplified without retries"""
        if not self.vectordb or not self.llm:
            print("[ERROR] System not fully initialized")
            return None, []
        
        print("🔍 Searching for similar vulnerability examples...")
        similar_examples = self.find_similar_vulnerabilities(user_code)
        
        if not similar_examples:
            print("[WARN] No similar vulnerability examples found")
            similar_examples = []
        
        print(f"📝 Found {len(similar_examples)} similar examples, building repair prompt...")
        
        try:
            print("🔧 Executing repair analysis...")
            
            # Build prompt
            repair_prompt = self.build_repair_prompt(user_code, similar_examples)
            
            # Get result from model
            raw_result = self.llm.invoke(repair_prompt)
            cleaned_result = self.clean_model_output(raw_result, repair_prompt)
            
            # Always return result, even if empty or incomplete
            if not cleaned_result.strip():
                print("⚠️ Model output is empty, providing fallback analysis...")
                cleaned_result = self._generate_fallback_analysis(user_code, similar_examples)
            
            print("✅ Repair analysis completed")
            return cleaned_result, similar_examples
            
        except Exception as e:
            print(f"❌ Error during processing: {str(e)}")
            # Provide fallback analysis even on error
            fallback_result = self._generate_fallback_analysis(user_code, similar_examples)
            return fallback_result, similar_examples
    
    def _generate_fallback_analysis(self, user_code, similar_examples):
        """Generate basic fallback analysis when model fails"""
        analysis = "## Vulnerability Analysis\n"
        analysis += "**Status**: Model analysis failed, providing basic assessment\n\n"
        
        # Basic vulnerability detection
        if 'gets(' in user_code:
            analysis += "**Detected Issue**: Buffer overflow vulnerability (CWE-120)\n"
            analysis += "**Problem**: Use of unsafe `gets()` function\n\n"
            analysis += "## Suggested Fix:\n"
            analysis += "```c\n"
            analysis += user_code.replace('gets(', 'fgets(').replace('gets(name)', 'fgets(name, sizeof(name), stdin)')
            analysis += "\n```\n\n"
            analysis += "## Key Changes:\n"
            analysis += "- Replace `gets()` with `fgets()` to prevent buffer overflow\n"
            analysis += "- Specify buffer size limit in `fgets()`\n"
        elif 'strcpy(' in user_code:
            analysis += "**Detected Issue**: Potential buffer overflow (CWE-120)\n"
            analysis += "**Problem**: Use of unsafe `strcpy()` function\n\n"
            analysis += "## Suggested Fix:\n"
            analysis += "```c\n"
            analysis += user_code.replace('strcpy(', 'strncpy(')
            analysis += "\n```\n\n"
            analysis += "## Key Changes:\n"
            analysis += "- Replace `strcpy()` with `strncpy()` for bounded copying\n"
        elif 'sprintf(' in user_code:
            analysis += "**Detected Issue**: Potential buffer overflow (CWE-120)\n"
            analysis += "**Problem**: Use of unsafe `sprintf()` function\n\n"
            analysis += "## Suggested Fix:\n"
            analysis += "```c\n"
            analysis += user_code.replace('sprintf(', 'snprintf(')
            analysis += "\n```\n\n"
            analysis += "## Key Changes:\n"
            analysis += "- Replace `sprintf()` with `snprintf()` for bounded formatting\n"
        else:
            analysis += "**Status**: No obvious vulnerabilities detected in basic scan\n"
            analysis += "**Recommendation**: Manual security review recommended\n\n"
            analysis += "## Original Code:\n"
            analysis += "```c\n"
            analysis += user_code
            analysis += "\n```\n"
        
        if similar_examples:
            analysis += f"\n## Referenced Examples:\n"
            for i, example in enumerate(similar_examples[:3], 1):
                cwe_id = example.metadata.get('cwe_id', 'Unknown')
                title = example.metadata.get('example_title', 'Unknown')
                analysis += f"- {cwe_id}: {title}\n"
        
        return analysis
    
    # === STEP 8: System Initialization ===
    def initialize(self, force_rebuild_db=False, force_recollect_cwe=False):
        """Initialize the entire system"""
        print("🚀 Initializing RAG Vulnerability Repair System...")
        
        # Build vector database
        if not self.build_or_load_vectordb(force_rebuild_db, force_recollect_cwe):
            print("[ERROR] Vector database initialization failed")
            return False
        
        # Load model
        if not self.load_llm():
            print("[ERROR] Model loading failed")
            return False
        
        print("✅ System initialization completed!")
        return True
    
    # === STEP 9: Interactive Interface ===
    def run_interactive(self):
        """Run interactive repair interface"""
        print("\n" + "="*60)
        print("🔒 RAG Vulnerability Repair System - Interactive Mode")
        print("="*60)
        print("Enter code snippets for vulnerability analysis and repair")
        print("Enter 'exit' to end program, 'help' to view instructions")
        print("="*60)
        
        while True:
            print("\nPlease enter your code snippet (multi-line input, enter 'END' to finish):")
            
            user_code_lines = []
            while True:
                try:
                    line = input()
                    if line.strip() == 'END':
                        break
                    elif line.strip().lower() == 'exit':
                        print("👋 Thank you for using!")
                        return
                    elif line.strip().lower() == 'help':
                        self.show_help()
                        break
                    user_code_lines.append(line)
                except KeyboardInterrupt:
                    print("\nProgram interrupted")
                    return
            
            if line.strip().lower() == 'help':
                continue
            
            user_code = '\n'.join(user_code_lines)
            
            if not user_code.strip():
                print("⚠️ Code input is empty, please re-enter")
                continue
            
            try:
                print("\n" + "="*50)
                print("🔍 Starting code vulnerability analysis...")
                
                result, similar_examples = self.repair_vulnerability(user_code)
                
                print("\n" + "="*50)
                if similar_examples:
                    print("📋 Referenced similar vulnerability examples:")
                    for i, example in enumerate(similar_examples, 1):
                        cwe_id = example.metadata.get('cwe_id', 'Unknown')
                        title = example.metadata.get('example_title', 'Unknown')
                        print(f"  {i}. {cwe_id} - {title}")
                
                print("\n" + "="*50)
                print("🔧 Vulnerability Analysis and Repair Results:")
                print("="*50)
                print(result)
                print("="*50)
                
                # Check if it contains code blocks
                code_blocks = re.findall(r'```[\s\S]*?```', result)
                if code_blocks:
                    print(f"\n✅ Generated {len(code_blocks)} code blocks")
                else:
                    print("\n📝 Analysis completed (may contain recommendations without code blocks)")
                    
            except Exception as e:
                print(f"❌ Error occurred during processing: {str(e)}")
                import traceback
                print(f"Detailed error: {traceback.format_exc()}")
            
            print("\nContinue analyzing other code? (y/n/exit)")
            choice = input().strip().lower()
            if choice in ['n', 'no', 'exit']:
                break
        
        print("👋 Thank you for using the RAG Vulnerability Repair System!")
    
    def show_help(self):
        """Display help information"""
        print("\n" + "="*50)
        print("📖 User Guide - RAG Vulnerability Repair System")
        print("="*50)
        print("🎯 System Features:")
        print("  ✓ Always provides analysis output")
        print("  ✓ Fallback analysis when model fails")
        print("  ✓ Basic vulnerability detection")
        print("\n📝 Usage:")
        print("1. Enter code snippet to be analyzed")
        print("2. System searches for similar vulnerabilities and generates repair solution")
        print("3. Provides repair recommendations or complete code")
        print("\n🔧 Supported Vulnerability Types:")
        print("   - Buffer Overflow (CWE-120, CWE-121, CWE-122)")
        print("   - Use After Free (CWE-416)")
        print("   - SQL Injection (CWE-89)")
        print("   - Cross-Site Scripting (CWE-79)")
        print("   - Memory Leak (CWE-401)")
        print("   - And more common vulnerability types...")
        print("\n💡 Tips:")
        print("   - Enter 'exit' to end program")
        print("   - System will always provide some form of analysis")
        print("   - Recommend providing complete functions or program segments")
        print("="*50)
    
    # === View collected CWE data statistics ===
    def show_cwe_statistics(self):
        """Display statistics of collected CWE data"""
        cache_path = Path(self.cwe_examples_file)
        if not cache_path.exists():
            print(f"[INFO] CWE data file does not exist: {self.cwe_examples_file}")
            return
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'collection_info' in data:
                info = data['collection_info']
                print(f"\n=== CWE Data Statistics ===")
                print(f"Total CWE Types: {info.get('total_cwes', 0)}")
                print(f"Total Examples: {info.get('total_examples', 0)}")
                print(f"CWE ID List: {info.get('cwe_ids', [])}")
            
            cwe_examples = data.get('cwe_examples', data)
            print(f"\n=== Number of Examples per CWE Type ===")
            for cwe_id, examples in cwe_examples.items():
                print(f"CWE-{cwe_id}: {len(examples)} examples")
            
        except Exception as e:
            print(f"[ERROR] Failed to read CWE data statistics: {e}")

def main():
    """Main program"""
    print("🔒 Integrated RAG Vulnerability Repair System (Simplified)")
    print("="*60)
    
    # Set paths
    model_path = "./llama3.1"
    db_dir = "./chroma_db"
    
    # Check model path
    if not Path(model_path).exists():
        print(f"[WARN] Model path does not exist: {model_path}")
        print("Please ensure Llama 3.1 model is downloaded to the specified path")
        model_path = input("Please enter the correct model path: ").strip()
    
    # Initialize system
    pipeline = IntegratedRAGPipeline(model_path=model_path, db_dir=db_dir)
    
    # Ask for initialization options
    print("\nSelect initialization mode:")
    print("1. Use existing data (if available)")
    print("2. Complete reconstruction")
    print("3. View CWE data statistics")
    
    choice = input("Please select (1/2/3): ").strip()
    
    if choice == "3":
        pipeline.show_cwe_statistics()
        return
    elif choice == "2":
        force_rebuild_db = True
        force_recollect_cwe = True
    else:  # choice == "1" or default
        force_rebuild_db = False
        force_recollect_cwe = False
    
    if not pipeline.initialize(force_rebuild_db=force_rebuild_db, force_recollect_cwe=force_recollect_cwe):
        print("[ERROR] System initialization failed")
        return
    
    # Start interactive interface
    pipeline.run_interactive()

if __name__ == "__main__":
    main()
