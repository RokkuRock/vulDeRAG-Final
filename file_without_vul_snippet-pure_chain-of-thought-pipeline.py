import json
import re
from pathlib import Path
from langchain_core.documents import Document
from typing import List
import argparse 

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
from new_cwe_crawler import CWECollector, get_common_cwe_ids

class IntegratedRAGPipeline:
    """Integrated RAG Vulnerability Repair System - Using DeepSeek-R1-Distill-Llama-8B (Simplified)"""
    
    def __init__(self, model_path="./DeepSeek-R1-Distill-Llama-8B", db_dir="./chroma_db"):
        self.model_path = model_path
        self.db_dir = db_dir
        self.vectordb = None
        self.llm = None
        self.cwe_collector = CWECollector(delay=1)
        self.cwe_examples_file = "cwe_examples.json"
    
    # 新增方法: 讀取程式碼文件
    def read_code_file(self, file_path):
        """讀取程式碼文件並返回內容"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                print(f"❌ 文件不存在: {file_path}")
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if not content.strip():
                print(f"⚠️ 文件內容為空: {file_path}")
                return None
            
            print(f"✅ 成功讀取文件: {file_path} ({len(content)} 字符)")
            return content
            
        except Exception as e:
            print(f"❌ 讀取文件時發生錯誤: {e}")
            return None

    # 新增方法: 處理單個文件的漏洞修復
    def repair_file_vulnerability(self, file_path):
        """處理單個文件的漏洞修復"""
        if not self.vectordb or not self.llm:
            print("[ERROR] 系統未完全初始化")
            return False
        
        # 讀取文件內容
        user_code = self.read_code_file(file_path)
        if user_code is None:
            return False
        
        try:
            print("\n" + "="*60)
            print(f"🔍 開始分析文件: {file_path}")
            print("="*60)
            
            result, similar_examples = self.repair_vulnerability(user_code)
            
            print("\n" + "="*50)
            if similar_examples:
                print("📋 參考的相似漏洞範例:")
                for i, example in enumerate(similar_examples, 1):
                    cwe_id = example.metadata.get('cwe_id', 'Unknown')
                    title = example.metadata.get('example_title', 'Unknown')
                    print(f"  {i}. {cwe_id} - {title}")
            
            print("\n" + "="*50)
            print("🔧 漏洞分析與修復結果:")
            print("="*50)
            print(result)
            print("="*50)
            
            # 檢查是否包含程式碼區塊
            code_blocks = re.findall(r'```[\s\S]*?```', result)
            if code_blocks:
                print(f"\n✅ 生成了 {len(code_blocks)} 個程式碼區塊")
            else:
                print("\n📝 分析完成 (可能包含建議但無程式碼區塊)")
            
            return True
                
        except Exception as e:
            print(f"❌ 處理過程中發生錯誤: {str(e)}")
            import traceback
            print(f"詳細錯誤: {traceback.format_exc()}")
            return False

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
            cwe_ids = get_common_cwe_ids()[:1000]  # Limit quantity to avoid taking too long
        
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
        """Convert CWE data to Document format - 區分修復前和修復後的程式碼"""
        documents = []

        def filter_metadata(meta_dict):
            """只保留基本型別的 metadata（str, int, float, bool, None）"""
            return {k: v for k, v in meta_dict.items() if isinstance(v, (str, int, float, bool, type(None)))}

        for cwe_id, examples in cwe_examples.items():
            # Handle different formats of cwe_id (could be string or integer)
            cwe_id_str = str(cwe_id)

            for i, example in enumerate(examples):
                is_fixed = example.get('is_fixed', False)
                code_type = "fixed" if is_fixed else "vulnerable"
                background_color = example.get('background_color', 'none')

                metadata = {
                    "cwe_id": f"CWE-{cwe_id_str}",
                    "vulnerability_type": f"CWE-{cwe_id_str}",
                    "example_title": example.get('title', f'Example {i+1}'),
                    "source": example.get('source', 'crawler'),
                    "file": f"cwe_{cwe_id_str}_example_{i+1}",
                    "bug_block_id": f"{cwe_id_str}_{i+1}",
                    "original_snippet": example.get('code', ''),
                    "code_type": code_type,
                    "is_fixed": is_fixed,
                    "background_color": background_color,
                    "doc_id": f"CWE-{cwe_id_str}_{code_type}_{i+1}"
                }

                # 可選：將 computed_styles 的背景色以文字保留（不保留 dict）
                if 'computed_styles' in example:
                    cs = example['computed_styles']
                    if isinstance(cs, dict):
                        if 'background-color' in cs:
                            metadata['computed_style_bg'] = cs['background-color']

                # Content format optimized for vector search
                content_prefix = "Fixed Code" if is_fixed else "Vulnerable Code"
                content = f"""Vulnerability Type: CWE-{cwe_id_str}
    Code Type: {content_prefix}
    Example Title: {example.get('title', f'Example {i+1}')}
    Code:
    {example.get('code', '')}"""

                documents.append(Document(
                    page_content=content,
                    metadata=filter_metadata(metadata)  # 過濾非法 metadata
                ))

        # 統計資訊
        total_docs = len(documents)
        vulnerable_docs = len([d for d in documents if not d.metadata.get('is_fixed', False)])
        fixed_docs = len([d for d in documents if d.metadata.get('is_fixed', False)])

        print(f"[INFO] Conversion completed: {total_docs} documents")
        print(f"[INFO] - Vulnerable code documents: {vulnerable_docs}")
        print(f"[INFO] - Fixed code documents: {fixed_docs}")

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
        """Load local DeepSeek-R1-Distill-Llama-8B model"""
        try:
            print("[INFO] Loading local DeepSeek-R1-Distill-Llama-8B model...")
            
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
            print("[SUCCESS] DeepSeek-R1-Distill-Llama-8B model loaded successfully!")
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
        """建構Chain-of-Thought Q&A格式的修復提示詞"""
        
        prompt = f"""作為專業的程式碼安全專家，請透過以下問答步驟來分析和修復程式碼漏洞。

    === 參考相似漏洞範例 ===
    """
        
        for i, example in enumerate(similar_examples, 1):
            cwe_id = example.metadata.get('cwe_id', 'Unknown')
            example_title = example.metadata.get('example_title', 'Unknown')
            original_snippet = example.metadata.get('original_snippet', '')
            
            prompt += f"""
    【參考範例 {i}】{cwe_id} - {example_title}
    漏洞程式碼:
    ```
    {original_snippet[:500]}...
    ```
    """
        
        prompt += f"""

    === 待修復的程式碼 ===
    ```
    {user_code}
    ```

    請按照以下Chain-of-Thought問答格式進行分析：

    Q1: 這段程式碼可能存在什麼類型的安全漏洞？
    A1: [請根據程式碼特徵和參考範例，識別可能的漏洞類型，例如：緩衝區溢出、使用後釋放、SQL注入等，並說明判斷依據]

    Q2: 漏洞具體位於程式碼的哪個位置？
    A2: [請指出具體的行數、函數名稱或程式碼區塊，說明為什麼這些位置存在安全風險]

    Q3: 這個漏洞可能造成什麼樣的安全威脅？
    A3: [請描述攻擊者可能如何利用此漏洞，以及可能造成的損害，如記憶體破壞、資料洩漏、權限提升等]

    Q4: 應該採用什麼修復策略來解決這個漏洞？
    A4: [請根據漏洞類型提出具體的修復方法，如邊界檢查、輸入驗證、記憶體管理改善等]

    Q5: 修復後的完整程式碼應該是什麼樣子？
    A5: **重要：必須提供完整的、可直接編譯執行的修復後程式碼，且不可以完全照抄向量資料庫找到的程式碼範例，必須憑自己創意與引用向量資料庫檢索到的範例中CWE的觀念與弱點概念，進行修改給出全新的程式碼方案，方案只能有一個Fixed code跟一個CWE編號**

    ```
    [在此處提供完整的修復後程式碼，包含所有必要的header、變數宣告、錯誤處理等]
    ```

    Q6: 修復過程中做了哪些關鍵改動？
    A6: [請詳細列出主要的程式碼變更點，說明每個改動如何解決原有的安全問題]

    Q7: 如何確保修復後不會引入新的安全問題？
    A7: [請說明修復策略如何徹底消除漏洞，以及採取了哪些額外的安全措施]

    Q8: 有什麼相關的安全編程建議可以預防類似漏洞？
    A8: [請提供相關的最佳實踐建議和預防類似漏洞的編程習慣]

    **注意事項：**
    1. 每個問題都必須完整回答
    2. Q5的修復後程式碼必須完整且可執行
    3. 確保修復不會引入新的安全問題
    4. 保持原有程式邏輯的正確性
    5. 每個Q與A的問題的輸出不得超過200個tokens

    請開始逐步回答每個問題："""
        
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

# ===== 修改位置3: 完全替換 main() 函數 =====
def main():
    """主程式 - 支援命令行參數"""
    try:
        print("🔒 程式開始執行...")  # 添加調試信息
        
        # 設置命令行參數解析
        parser = argparse.ArgumentParser(description='RAG 漏洞修復系統')
        parser.add_argument('-i', '--input', type=str, help='指定要分析的程式碼文件路徑')
        parser.add_argument('--model-path', type=str, default="./DeepSeek-R1-Distill-Llama-8B", 
                           help='指定模型路徑 (預設: ./DeepSeek-R1-Distill-Llama-8B)')
        parser.add_argument('--db-dir', type=str, default="./chroma_db", 
                           help='指定向量資料庫目錄 (預設: ./chroma_db)')
        parser.add_argument('--rebuild', action='store_true', 
                           help='強制重建向量資料庫')
        parser.add_argument('--recollect', action='store_true', 
                           help='強制重新收集 CWE 資料')
        parser.add_argument('--stats', action='store_true', 
                           help='顯示 CWE 資料統計')
        
        print("🔍 解析命令行參數...")  # 添加調試信息
        args = parser.parse_args()
        print(f"📋 解析結果: input={args.input}, model_path={args.model_path}")  # 添加調試信息
        
        print("🔒 整合式 RAG 漏洞修復系統 (簡化版)")
        print("="*60)
        
        # 如果只是要查看統計資訊
        if args.stats:
            print("📊 進入統計模式...")
            pipeline = IntegratedRAGPipeline(model_path=args.model_path, db_dir=args.db_dir)
            pipeline.show_cwe_statistics()
            return
        
        # 如果指定了輸入文件，進行文件分析模式
        if args.input:
            print(f"📁 進入文件分析模式: {args.input}")
            
            # 檢查文件是否存在
            if not Path(args.input).exists():
                print(f"❌ 錯誤: 文件不存在 - {args.input}")
                print(f"📂 當前工作目錄: {Path.cwd()}")
                print(f"📋 目錄內容:")
                try:
                    for item in Path.cwd().iterdir():
                        if item.is_file() and item.suffix in ['.c', '.cpp', '.py', '.java']:
                            print(f"   - {item.name}")
                except Exception as e:
                    print(f"   無法列出目錄內容: {e}")
                return
            
            print("🚀 初始化系統...")
            # 檢查模型路徑
            if not Path(args.model_path).exists():
                print(f"[WARN] 模型路徑不存在: {args.model_path}")
                print("請確保 DeepSeek-R1-Distill-Llama-8B 模型已下載到指定路徑")
                model_path = input("請輸入正確的模型路徑 (或按 Enter 跳過): ").strip()
                if not model_path:
                    print("⚠️ 跳過模型檢查，繼續執行...")
                else:
                    args.model_path = model_path
            
            # 初始化系統
            pipeline = IntegratedRAGPipeline(model_path=args.model_path, db_dir=args.db_dir)
            
            print("⚙️ 正在初始化系統組件...")
            if not pipeline.initialize(force_rebuild_db=args.rebuild, force_recollect_cwe=args.recollect):
                print("[ERROR] 系統初始化失敗")
                return
            
            print("🔧 開始處理文件...")
            # 處理指定的文件
            success = pipeline.repair_file_vulnerability(args.input)
            if success:
                print(f"\n✅ 文件 {args.input} 分析完成！")
            else:
                print(f"\n❌ 文件 {args.input} 分析失敗！")
            return
        
        # 沒有指定文件時，進入互動模式
        print("\n⚠️ 未指定輸入文件，進入互動模式")
        print("💡 提示: 使用 -i <文件名> 參數可直接分析指定文件")
        
        # 檢查模型路徑
        if not Path(args.model_path).exists():
            print(f"[WARN] 模型路徑不存在: {args.model_path}")
            print("請確保 DeepSeek-R1-Distill-Llama-8B 模型已下載到指定路徑")
            model_path = input("請輸入正確的模型路徑: ").strip()
            if not model_path:
                print("❌ 未提供有效的模型路徑，程式結束")
                return
            args.model_path = model_path
        
        # 初始化系統
        pipeline = IntegratedRAGPipeline(model_path=args.model_path, db_dir=args.db_dir)
        
        print("\n選擇初始化模式:")
        print("1. 使用現有資料 (如果可用)")
        print("2. 完全重建")
        print("3. 查看 CWE 資料統計")
        
        choice = input("請選擇 (1/2/3): ").strip()
        
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
            print("[ERROR] 系統初始化失敗")
            return
        
        # 啟動互動介面
        pipeline.run_interactive()
        
    except KeyboardInterrupt:
        print("\n\n⚠️ 用戶中斷程式執行")
    except Exception as e:
        print(f"\n❌ 程式執行時發生未預期的錯誤:")
        print(f"錯誤類型: {type(e).__name__}")
        print(f"錯誤訊息: {str(e)}")
        import traceback
        print(f"詳細追蹤:")
        traceback.print_exc()
    finally:
        print("🔚 程式結束")

if __name__ == "__main__":
    main()
