# Research Papers Tracker (Notion Export)

- Source CSV: `d:\JustainoTitaino\Descargas\fd6dd5a2-7dd9-42a4-87c7-6a5c0a8ae677_ExportBlock-eb360096-9e0e-4757-befa-75a8f93a428f\ExportBlock-eb360096-9e0e-4757-befa-75a8f93a428f-Part-1\Research Papers Tracker 2d3b8407f98f800899e8f16a6de1481b_all.csv`
- Last update (generated): 2026-05-23 17:05:45
- Total papers: **9**

## Quick Stats

### By Year
- 2025: 8
- 2024: 1

### By Venue / Type
- ArXiv: 7
- Conference: 2

### By Method Class
- Agent-based: 5
- LLM-based: 3
- PoC generation: 1

## Comparative Table

| # | Year | Title | Venue / Type | Method Class | Vulnerability Focus | LLMs evaluated | Paper | Code/Data |
|---:|---:|---|---|---|---|---|---|---|
| 1 | 2025 | PwnGPT: Automatic Exploit Generation Based on Large Language Models | Conference | LLM-based | Stack Overflow,Format String,Integer Overflow,Use-After-Fre... | qwen-plus, qwen-max, GPT-4o, OpenAI o1-preview | [link](https://aclanthology.org/2025.acl-long.562.pdf) | [link](https://github.com/aeg-hit/PwnGPT) |
| 2 | 2025 | LLM Agents for Automated Web Vulnerability Reproduction: Are We There Yet? | ArXiv | Agent-based | CSRF,Path Traversal,RCE,SQLI,SSRF,XSS | GPT-4.1; Claude-Sonnet-4; Gemini-2.5-Pro | [link](https://arxiv.org/pdf/2510.14700v1) | [link](https://figshare.com/s/7e55eaaaca0b0146ee62) |
| 3 | 2025 | Good News for Script Kiddies? Evaluating Large Language Models for Automated Exploit Generation | ArXiv | LLM-based | Buffer Overflow,return-to-libc,Format String,Race Condition... | GPT-4o; GPT-4o-mini; Llama3 (8B); Dolphin-Mistral (7B); Dolphin-Phi (... | [link](https://arxiv.org/pdf/2505.01065) | [link](http://anonymous.4open.science/r/AEG) |
| 4 | 2025 | From CVE Entries to Verifiable Exploits: An Automated Multi-Agent Framework for Reproducing CV... | ArXiv | Agent-based | Broad coverage across many ecosystems: in the large-scale e... | They evaluate "ten leading models" for integration and list them in T... | [link](https://arxiv.org/pdf/2509.01835) | https://www.notion.so... |
| 5 | 2025 | CYBERGYM: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale | ArXiv | Agent-based | Primarily C/C++ sanitizer-detectable issues (memory safety ... | Backbone LLMs evaluated (11 total): GPT-4.1; GPT-5; o4-mini; Claude-3... | [link](https://arxiv.org/pdf/2506.02548) | [link](https://huggingface.co/datasets/sunblaze-ucb/cybergym) |
| 6 | 2025 | CVE-Bench: A Benchmark for AI Agents' Ability to Exploit Real-World Web Application Vulnerabil... | Conference | Agent-based | Web-application CVEs (open-source, platform-independent, re... | Primary model used for experiments: gpt-4o-2024-11-20. Additional bas... | [link](https://arxiv.org/pdf/2503.17332) | [link](https://github.com/uiuc-kang-lab/cve-bench) |
| 7 | 2025 | Automated Vulnerability Validation and Verification: A Large Language Model Approach | ArXiv | LLM-based | Memory Overflow,DoS,Memory Corruption,RCE | GPT-4o; Qwen3-225B; DeepSeek V3; Mistral AI; Llama-3.3-70B; Gemini 2.... | [link](https://arxiv.org/pdf/2509.24037) | [link](https://github.com/arlotfi79/CVE_Experiments) |
| 8 | 2025 | A Systematic Study on Generating Web Vulnerability Proof-of-Concepts Using Large Language Mode... | ArXiv | PoC generation | 100 reproducible real-world web CVEs spanning five CWE cate... | GPT-4o and DeepSeek-R1. | [link](https://arxiv.org/pdf/2510.10148v1) | https://www.notion.so... |
| 9 | 2024 | LLM Agents can Autonomously Exploit One-day Vulnerabilities | ArXiv | Agent-based | One-day vulns,Privilege Escalation,ACIDRain,RCE | GPT-4; GPT-3.5; OpenHermes-2.5-Mistral-7B; LLaMA-2 Chat (70B/13B/7B);... | [link](https://arxiv.org/pdf/2404.08144) | https://www.notion.so... |

## Detailed Paper Notes

### 1. PwnGPT: Automatic Exploit Generation Based on Large Language Models

- Year: 2025
- Venue / Type: Conference
- Method Class: LLM-based
- Authors: Wanzong Peng; Lin Ye; Xuetao Du; Hongli Zhang; Dongyang Zhan; Yunting Zhang; Yicheng Guo; Chen Zhang
- Paper link: https://aclanthology.org/2025.acl-long.562.pdf
- Code / Data link: https://github.com/aeg-hit/PwnGPT

#### Approach (full)
LLM-based

#### Paper Contribution
Builds a CTF "pwn" benchmark for binary exploit generation, evaluates multiple LLMs across key exploitation sub-capabilities, and proposes PwnGPT, a modular LLM-agent framework (analysis + generation + verification) that improves exploit completion rates versus directly prompting LLMs.

#### Target Vulnerability Types
Stack Overflow,Format String,Integer Overflow,Use-After-Free,Heap Overflow

#### LLMs Evaluated
qwen-plus, qwen-max, GPT-4o, OpenAI o1-preview

#### Evaluation Metrics
Benchmark success counts across four capability tests (key info analysis, vulnerability location, exploit chain construction, code generation) over 19 challenges. 
End-to-end exploit completion rate / number of challenges solved, comparing "direct LLM prompting" vs PwnGPT. Reported improvements include 26.3% -> 57.9% with o1-preview and 21.1% -> 36.8% with GPT-4o on their benchmark. 
Verification-module impact measured by whether failed/non-executable exploits become executable after limited iterations (they report 3/30 becoming executable for qwen-plus, but none becoming fully feasible exploits).

### 2. LLM Agents for Automated Web Vulnerability Reproduction: Are We There Yet?

- Year: 2025
- Venue / Type: ArXiv
- Method Class: Agent-based
- Authors: Bin Liu; Yanjie Zhao; Guoai Xu; Haoyu Wang
- Paper link: https://arxiv.org/pdf/2510.14700v1
- Code / Data link: https://figshare.com/s/7e55eaaaca0b0146ee62

#### Approach (full)
LLM-agent-based vulnerability reproduction in a safe containerized setting with standardized prompts and structured JSON outputs. The study decomposes reproduction into four tasks (environment setup, vulnerability localization, PoC generation with verification, and end-to-end reproduction). Agents are restricted to command-line interactions (browser-based interactions prohibited), and outputs must include generated Docker artifacts, exploit PoC code, verification oracles, and a step-by-step reproduction document.

#### Paper Contribution
Provides the first comprehensive evaluation of state-of-the-art LLM agents for automated web vulnerability reproduction (turning vulnerability reports into working PoC exploits). It (1) evaluates 20 agents across 16 capability dimensions on 3 representative CVEs, (2) selects OpenHands, SWE-agent, and CAI for deeper evaluation, and (3) constructs a benchmark of 80 real-world CVEs with containerized reproduction environments and verification oracles, revealing consistently low end-to-end success (<25%) and a major "execute PoC but fail to trigger vulnerability" gap, plus strong sensitivity to authentication information.

#### Target Vulnerability Types
CSRF,Path Traversal,RCE,SQLI,SSRF,XSS

#### LLMs Evaluated
GPT-4.1; Claude-Sonnet-4; Gemini-2.5-Pro

#### Evaluation Metrics
Environment Setup Success Rate.
 
Vulnerability Localization accuracy (Top-K, evaluated as Top-3) at file/function/line granularities. 
2510.14700v1PoC Generation success split into Execution Success Rate vs Vulnerability Trigger Success Rate. 
2510.14700v1End-to-End Success Rate reported as Success@1 and Success@3. 

Efficiency metrics: execution time, token consumption, and estimated USD cost. 

Robustness analyses: "with vs without enhanced reasoning" (Figure 4) and authentication scenarios (manual token vs agent login vs no auth info; Table 8), including the reported average performance degradation under incomplete authentication information.

### 3. Good News for Script Kiddies? Evaluating Large Language Models for Automated Exploit Generation

- Year: 2025
- Venue / Type: ArXiv
- Method Class: LLM-based
- Authors: David Jin; Qian Fu; Yuekang Li
- Paper link: https://arxiv.org/pdf/2505.01065
- Code / Data link: http://anonymous.4open.science/r/AEG

#### Approach (full)
LLM-based

#### Paper Contribution
Performs a systematic study of LLMs for automated exploit generation, measuring both (1) how willing models are to cooperate with exploit requests and (2) how technically effective their generated exploits are, using SEED Labs plus refactored variants to reduce memorization bias; introduces an automated LLM-based attacker to standardize multi-turn prompting across models.

#### Target Vulnerability Types
Buffer Overflow,return-to-libc,Format String,Race Condition,Dirty COW

#### LLMs Evaluated
GPT-4o; GPT-4o-mini; Llama3 (8B); Dolphin-Mistral (7B); Dolphin-Phi (2.7B).

#### Evaluation Metrics
Cooperativeness: average percentage of cooperative responses during iterative prompting, reported per vulnerability type and per model. 
Effectiveness: number of "mistakes" in generated exploit code that prevent the exploit from working, compared against reference solutions; evaluated on both original labs and refactored/obfuscated versions. 
Robustness to memorization: performance drop from original labs to refactored labs is used as an indicator of potential training-data leakage or reliance on superficial cues.

### 4. From CVE Entries to Verifiable Exploits: An Automated Multi-Agent Framework for Reproducing CVEs

- Year: 2025
- Venue / Type: ArXiv
- Method Class: Agent-based
- Authors: Saad Ullah; Praneeth Balasubramanian; Wenbo Guo; Amanda Burnett; Hammond Pearce; Christopher Kruegel; Giovanni Vigna; Gianluca Stringhini
- Paper link: https://arxiv.org/pdf/2509.01835
- Code / Data link: https://www.notion.soThey state they "will open source" the framework/source code, logs (including agent conversations), and the dataset of 428 reproduced CVEs, but the paper itself does not provide a specific repository URL in the text shown.

#### Approach (full)
CVE reproduction pipeline using four modules-Processor, Builder, Exploiter, and CTF Verifier-and within modules, developer + critic agents in an iterative ReAct-style loop ("self-critique") to improve reliability. The system builds a structured knowledge base from CVE resources, reconstructs the vulnerable environment, develops a PoC exploit, and then generates and validates a verifier that returns a "flag" when exploitation is confirmed.

#### Paper Contribution
Introduces CVE-GENIE, an LLM-based multi-agent system that takes a CVE entry, gathers relevant resources, rebuilds a vulnerable environment, generates a working exploit/PoC, and generates a verifier that checks whether the exploit truly triggers the vulnerability (CTF-style). It reports reproducing ~51% (428/841) CVEs from Jun 2024-May 2025 at an average cost of $2.77 per CVE, aiming to create high-quality reproducible benchmarks for downstream security research.

#### Target Vulnerability Types
Broad coverage across many ecosystems: in the large-scale evaluation they report reproduction across 141 CWEs, 22 programming languages, and 267 projects. They also note web vulnerabilities (e.g., XSS, CSRF, SQLi, path traversal) are most reproducible, while memory-safety bugs (C/C++), concurrency issues, and UI-dependent flaws are hardest to verify.

#### LLMs Evaluated
They evaluate "ten leading models" for integration and list them in Table 3: o3, o4-mini, Claude 3.7 Sonnet, Claude 3.5 Sonnet, Gemini 2.5 Pro, Gemini 2.5 Flash, Llama 4 Maverick, Qwen 3, DeepSeek V3, DeepSeek R1. 

They also assign o4-mini as the Knowledge Builder model, and select specific developer/critic pairings per module (e.g., Builder developer o4-mini + critic o3; Exploiter developer o3 + critic o4-mini; Verifier developer o3 + critic o3).

#### Evaluation Metrics
Primary outcome: CVE reproduction success (CVE "marked as reproduced" after passing verification, then stored with VM snapshot + exploit + verifier). 

Scale result: number/percentage of CVEs reproduced (e.g., 428/841 for Jun 2024-May 2025). 

Cost/time: average cost per CVE (reported $2.77 in the abstract; they also discuss per-run budgets and observed typical cost/time in experiments). 

Module-level effectiveness (model selection): manual verification vs LLM-reported success, and critic evaluation using TPR/TNR when selecting critic models. 

Robustness: ablations removing CVE context fields (advisory, patch commit, etc.) and design ablations removing components (knowledge builder, feedback loops, critics, single monolithic agent).

### 5. CYBERGYM: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale

- Year: 2025
- Venue / Type: ArXiv
- Method Class: Agent-based
- Authors: Zhun Wang; Tianneng Shi; Jingxuan He; Matthew Cai; Jialin Zhang; Dawn Song
- Paper link: https://arxiv.org/pdf/2506.02548
- Code / Data link: https://huggingface.co/datasets/sunblaze-ucb/cybergym

#### Approach (full)
This is PoC generation for vulnerability reproduction, not end-to-end exploit payload crafting. The core task is: agent receives a text vulnerability description + the pre-patch codebase, and iteratively generates a single raw input file (binary or text) to feed the target program. 

The agent tests candidates via a provided script (http://submit.sh/) inside a modular, containerized environment. 

Success is decided by sanitizer-based execution across pre-patch and post-patch builds. The benchmark also defines four information levels (Level 0-3) ranging from no description (open-ended discovery) to providing stack traces and the patch diff for "one-day-like" settings.

#### Paper Contribution
Introduces CyberGym, a large-scale, execution-verified benchmark for evaluating AI agents on vulnerability reproduction: given a vulnerability description and the vulnerable codebase, the agent must generate a PoC input file that triggers the bug in the pre-patch build but not in the post-patch build. It contains 1,507 real-world vulnerabilities across 188 projects (sourced from OSS-Fuzz), and the paper reports extensive evaluation across multiple agent frameworks and frontier LLMs. Beyond benchmarking, it also reports real-world security impact: identifying incomplete patches and discovering zero-day vulnerabilities during agent runs.

#### Target Vulnerability Types
Primarily C/C++ sanitizer-detectable issues (memory safety / undefined behavior). The benchmark covers 28 sanitizer crash types, including (examples): heap-buffer-overflow (read/write), heap-use-after-free (read/write), stack-buffer-overflow (read/write), null dereference, wild-address read/write, use-of-uninitialized-value, double free, etc.

#### LLMs Evaluated
Backbone LLMs evaluated (11 total): GPT-4.1; GPT-5; o4-mini; Claude-3.7-Sonnet; Claude-Sonnet-4; Gemini-2.5-Flash; Qwen3-235B-A22B; DeepSeek-V3; SWE-Gym-32B; R2E-Gym-32B; OpenHands-LM-32B. (They also use GPT-4.1 in dataset construction to filter/rephrase commit messages into vulnerability descriptions.)

#### Evaluation Metrics
Main benchmark metric: success rate = % of instances where the agent generates a PoC such that (i) it triggers a sanitizer crash in the pre-patch build and (ii) does not trigger a sanitizer crash in the post-patch build (to ensure it reproduces the patched bug rather than "any crash"). They also analyze performance by difficulty level (0-3), by PoC length/complexity, by agent step counts, and they report real-world impact counts (incomplete patches, zero-days) discovered via generated PoCs.

### 6. CVE-Bench: A Benchmark for AI Agents' Ability to Exploit Real-World Web Application Vulnerabilities

- Year: 2025
- Venue / Type: Conference
- Method Class: Agent-based
- Authors: Yuxuan Zhu; Antony Kellermann; Dylan Bowman; Philip Li; Akul Gupta; Adarsh Danda; Richard Fang; Conner Jensen; Eric Ihli; Jason Benn; Jet Geronimo; Avi Dhir; Sudhit Rao; Kaicheng Yu; Twm Stone; Daniel Kang
- Paper link: https://arxiv.org/pdf/2503.17332
- Code / Data link: https://github.com/uiuc-kang-lab/cve-bench

#### Approach (full)
Agent-driven exploitation in an isolated sandbox. For each CVE, CVE-Bench provides:

- A containerized vulnerable web application (typically web-app container + database container + optional services; orchestrated via compose.yml). 

- A task specification that asks the agent to achieve at least one of eight standard attack goals, with disallowed attacks listed (e.g., no attacking other hosts/ports; no brute force). 

- Two lifecycle settings: zero-day (no vuln info; agent must find and exploit) vs one-day (agent receives NVD high-level vulnerability description). 

- An evaluation server inside the target (port 9091) that automatically checks success via /done.

#### Paper Contribution
Introduces CVE-Bench, a real-world benchmark to evaluate whether LLM agents can exploit 40 critical-severity web-application CVEs. It provides a sandbox framework with containerized vulnerable targets, standardizes success into eight "standard attacks", and implements an automatic evaluation server to grade agent exploits. It evaluates three agent frameworks (Cy-Agent, Teams of Agents, AutoGPT) under zero-day vs one-day settings and finds agents exploit up to 10% (zero-day) and 13% (one-day) vulnerabilities with five attempts.

#### Target Vulnerability Types
Web-application CVEs (open-source, platform-independent, reproducible) from NVD, selected within May 1, 2024-June 14, 2024, all critical (CVSS v3.x ≥ 9.0). The benchmark includes varied application types (e.g., content management/WordPress and plugins, AI/ML apps, business management apps, web infrastructure, libraries/packages, monitoring, e-commerce, mail server). 

(They do not label each CVE by CWE in the main description; instead they standardize evaluation by "attack targets.")

#### LLMs Evaluated
Primary model used for experiments: gpt-4o-2024-11-20. 

Additional baseline: T-Agent with Llama 3.1 (Meta) is evaluated and achieves 0 CVEs exploited.

#### Evaluation Metrics
Success rate: Success@1 and Success@5 (five attempts) under zero-day and one-day settings; success means achieving at least one standard attack goal. 

Cost metrics per task: average input/output tokens, runtime (seconds), and estimated USD cost (Table 4). 

Exploit composition: distribution of which standard attacks were achieved in successful cases (Figure 4). 

Failure-mode analysis: frequency of annotated failure modes (limited task understanding, incorrect focus, insufficient exploration, tool misuse, inadequate reasoning) (Table 5).

### 7. Automated Vulnerability Validation and Verification: A Large Language Model Approach

- Year: 2025
- Venue / Type: ArXiv
- Method Class: LLM-based
- Authors: Alireza Lotfi; Charalampos Katsis; Elisa Bertino
- Paper link: https://arxiv.org/pdf/2509.24037
- Code / Data link: https://github.com/arlotfi79/CVE_Experiments

#### Approach (full)
LLM-based

#### Paper Contribution
Introduces an end-to-end, multi-step pipeline using LLMs + RAG to extract CVE information, generate containerized environments and exploit code, iteratively refine/compile/execute artifacts, and validate success using generated test cases; it also reports large-scale reproduction results and highlights inconsistencies in CVE disclosures.

#### Target Vulnerability Types
Memory Overflow,DoS,Memory Corruption,RCE

#### LLMs Evaluated
GPT-4o; Qwen3-225B; DeepSeek V3; Mistral AI; Llama-3.3-70B; Gemini 2.5 Flash.

#### Evaluation Metrics
Reproduction success rate: 71/102 CVEs reproduced (≈70%), selected from 2020-2025. 
Coverage: 55 libraries/projects across 9 programming languages; among successes, exploits in 7 languages across 40 open-source projects. 
Outcome breakdown: successes include auto-verified (60), intervention-assisted (7), verification-assisted (4); failures are categorized (code generation, environment setup, both, non-verifiable). 
PoC availability effect: 48/71 reproduced CVEs had a reference PoC (≈68%), and PoC presence tends to reduce iteration count. 
Multi-container prevalence: 20/71 reproduced CVEs (≈28%) required multi-container setups. 
Execution time: average 4min25s per successful exploit (range 40s-60min, with the 60min case noted as a single outlier). 
Model comparison on a 10-CVE subset: GPT-4o is reported as the only model completing all pipeline steps correctly; other models fail at later steps (often execution/environment or refusals in Gemini's case)

### 8. A Systematic Study on Generating Web Vulnerability Proof-of-Concepts Using Large Language Models

- Year: 2025
- Venue / Type: ArXiv
- Method Class: PoC generation
- Authors: Mengyao Zhao; Kaixuan Li; Lyuye Zhang; Wenjing Dang; Chenggong Ding; Sen Chen; Zheli Liu
- Paper link: https://arxiv.org/pdf/2510.10148v1
- Code / Data link: https://www.notion.soNot published.

#### Approach (full)
PoC generation (not "full exploit weaponization") driven by LLM prompting, evaluated progressively in four phases:
1. baseline PoC generation from public artifacts across three disclosure scenarios,
2. failure analysis by decomposing PoC generation into explicit sub-tasks (to localize where models fail),
3. context supplementation (manual reconstruction of missing vulnerability + navigation context at file-level and function-level),
4. adaptive reasoning prompts combining chain-of-thought (CoT), in-context learning (ICL), and real-time feedback validators (including an attack payload validator and an execution path validator using Xdebug traces).

#### Paper Contribution
First systematic empirical study of LLM-based PoC generation for web application vulnerabilities using only publicly disclosed information across three disclosure stages: description-only (newly disclosed), description+patch (1-day), and description+patch+vulnerable file (N-day). They evaluate GPT-4o and DeepSeek-R1 on 100 reproducible real CVEs across five CWE categories, analyze why PoC generation fails via a sub-task decomposition, quantify benefits of context granularity (file vs function level), and show large gains from adaptive prompting (CoT, ICL, and real-time feedback validators). They report that some LLM-generated PoCs were accepted by NVD and Exploit-DB.

#### Target Vulnerability Types
100 reproducible real-world web CVEs spanning five CWE categories:
- CWE-79 (XSS)
- CWE-89 (SQLi)
- CWE-352 (CSRF)
- CWE-78 (OS command injection)
- CWE-434 (unrestricted file upload)

#### LLMs Evaluated
GPT-4o and DeepSeek-R1.

#### Evaluation Metrics
PoC generation success rates under three input scenarios (S1/S2/S3), with a conservative criterion: each vulnerability is run in three independent trials and counted successful only if all three produce functional PoCs (temperature set to 0). 

Ratesuccess and Ratedistribution (PoC format distribution) definitions. 

Failure-cause quantification: context deficiency (vulnerability context, navigation context) vs capability limitation (identification failure, reasoning failure), with formulas and breakdowns. 

Comparative success after context supplementation (file vs function level) and after adaptive reasoning prompts (CoT+ICL+feedback). 

Practical cost/time notes (experiment runtime/cost comparison between models) and human effort to build/validate environments.

### 9. LLM Agents can Autonomously Exploit One-day Vulnerabilities

- Year: 2024
- Venue / Type: ArXiv
- Method Class: Agent-based
- Authors: Richard Fang; Rohan Bindu; Akul Gupta; Daniel Kang
- Paper link: https://arxiv.org/pdf/2404.08144
- Code / Data link: https://www.notion.soNot provided in the document.

#### Approach (full)
LLM-based autonomous exploitation via a single ReAct agent (LangChain; OpenAI Assistants API for OpenAI models) with tool access (web browsing interactions, terminal, web search, file editing, code interpreter) and access to the CVE description; the prompt is described as detailed but is withheld publicly for ethical reasons.

#### Paper Contribution
Builds a benchmark of 15 reproducible real-world one-day vulnerabilities (14 CVEs + ACIDRain), then evaluates a simple tool-using ReAct LLM agent across 10 LLMs and two vulnerability scanners; finds that GPT-4 exploits 87% when given the CVE description, while all other tested models and scanners achieve 0%, and shows GPT-4 performance drops sharply without the CVE description.

#### Target Vulnerability Types
One-day vulns,Privilege Escalation,ACIDRain,RCE

#### LLMs Evaluated
GPT-4; GPT-3.5; OpenHermes-2.5-Mistral-7B; LLaMA-2 Chat (70B/13B/7B); Mixtral-8x7B Instruct; Mistral (7B) Instruct v0.2; Nous Hermes-2 Yi (34B); OpenChat 3.5

#### Evaluation Metrics
Success rate: pass@1 and pass@5, manually judged exploitation success. 
Cost: dollar cost estimated from token counts using OpenAI API prices "at the time of writing." 
Additional analyses: success with and without CVE descriptions; fraction of correct vulnerability identification when CVE descriptions are removed; number of agent actions per vulnerability.

