# LLM-Based Vulnerability Repair with RAG & Chain-of-Thought

## 📌 Project Overview

This project investigates the effectiveness of Large Language Models (LLMs) in automatically detecting and repairing security vulnerabilities. Specifically, it conducts a comparative ablation study to isolate the impact of **Retrieval-Augmented Generation (RAG)** and **Few-Shot Chain-of-Thought (CoT)** prompting on repair quality.

Using **DeepSeek-R1-Distill-Llama-8B** as the core model, the system is evaluated across 10 distinct CWE (Common Weakness Enumeration) categories, ranging from memory safety issues in C (CWE-121, CWE-416) to logic flaws in Python (CWE-22, CWE-502).

### Key Research Questions

- **Does RAG improve architectural fixes?** (e.g., switching from `strcat` to `sqlite3_prepare_v2` for SQLi)
- **Does Few-Shot CoT improve reliability?** (e.g., preventing hallucinations in complex logic)
- **How do these techniques interact?** (e.g., does RAG + CoT yield the optimal result?)

## 🚀 Key Features

### Automated Knowledge Base Construction
- Custom crawler (`new_cwe_crawler.py`) extracts "Vulnerable" vs. "Fixed" code pairs from MITRE CWE
- Uses Selenium to detect "Fixed" code blocks via computed CSS styles (e.g., `#CCCCFF` background)

### Vector Database Integration
- Uses ChromaDB with `sentence-transformers/all-MiniLM-L6-v2` embeddings
- Retrieves top-k similar vulnerability fixes to ground the LLM's generation

### 2×2 Experimental Matrix
1. **Zero-Shot (Baseline)**: Raw model inference
2. **Zero-Shot + RAG**: External context without reasoning guidance
3. **Few-Shot (CoT)**: Static reasoning guidance without external context
4. **Few-Shot + RAG (Hybrid)**: Combined dynamic context and structured reasoning

## 📂 Repository Structure

```
.
├── 📁 source_code/
│   ├── new_cwe_crawler.py              # Scraper for MITRE CWE (Selenium/BS4)
│   ├── cwe_statistics.py               # Statistics tool for dataset validation
│   ├── zero_shot_without_rag.py        # Pipeline 1: Baseline (Control Group)
│   ├── zero_shot_with_rag.py           # Pipeline 2: RAG Context Only
│   ├── few_shot_without_rag.py         # Pipeline 3: Static CoT Reasoning
│   └── few_shot_with_vul_snippet...py  # Pipeline 4: RAG + CoT (Hybrid System)
├── 📁 artifacts/
│   ├── cwe_examples.json               # Raw dataset from crawler
│   ├── 📁 chroma_db/                   # Persisted Vector Database
│   └── 📁 evaluation_results/          # Model outputs (Fixed source files)
├── 📁 test_cases/                      # Vulnerable subject programs (CWE-89, 416, etc.)
└── README.md
```

## 🛠️ Installation & Setup

### 1. Prerequisites

- Python 3.8+
- Google Chrome (required for Selenium crawling)
- GPU: Recommended (16GB+ VRAM) for local inference

### 2. Install Dependencies

```bash
pip install torch transformers accelerate bitsandbytes
pip install langchain langchain-huggingface langchain-chroma sentence-transformers
pip install selenium beautifulsoup4 requests
```

### 3. Model Setup

The project defaults to **DeepSeek-R1-Distill-Llama-8B**. Ensure the model is downloaded locally or accessible via HuggingFace Hub.

```python
# Update 'model_path' in the scripts if your path differs:
# self.model_path = "./DeepSeek-R1-Distill-Llama-8B"
```

## 🧪 Usage Instructions

### Step 1: Build the Knowledge Base (Optional)

If you do not have `cwe_examples.json` or `chroma_db`, run the crawler first.

```bash
python new_cwe_crawler.py
# Select Option 1 (Selenium) -> Option 1 (Common Vulnerabilities)
```

### Step 2: Run the Experimental Pipelines

You can evaluate any vulnerable file using the four distinct pipelines.

#### A. Zero-Shot Baseline (No RAG)

Pure model performance without external help.

```bash
python zero_shot_without_rag.py -i test_cases/cwe89.c
```

#### B. Zero-Shot with RAG

Injects retrieved CWE examples into the prompt.

```bash
python zero_shot_with_rag.py -i test_cases/cwe89.c --rebuild
```

*(Use `--rebuild` only on the first run to initialize the Vector DB)*

#### C. Few-Shot Chain-of-Thought (No RAG)

Uses static reasoning examples to guide the model's logic.

```bash
python few_shot_without_rag.py -i test_cases/cwe89.c
```

#### D. Few-Shot + RAG (Hybrid)

Combines retrieved context with structured reasoning steps.

```bash
python few_shot_with_vul_snippet-pure_chain-of-thought-pipeline.py -i test_cases/cwe89.c
```

## 📊 Evaluation

Results are saved in `artifacts/evaluation_results/` with repaired source code for each pipeline configuration.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

[Add your license here]

## 📧 Contact

[Add your contact information here]
