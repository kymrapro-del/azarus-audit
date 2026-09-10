# Benchmark azarus_audit

- Cas : 24
- Correspondance exacte : 24/24
- Precision : 1.0
- Rappel : 1.0
- F1 : 1.0

| Cas | Attendu | Detecte | OK |
|---|---|---|---|
| sqli_concat | ['CWE-89'] | ['CWE-89'] | oui |
| sqli_fstring | ['CWE-89'] | ['CWE-89'] | oui |
| sqli_percent | ['CWE-89'] | ['CWE-89'] | oui |
| sqli_safe_param | [] | [] | oui |
| sqli_safe_const | [] | [] | oui |
| cmd_os_system | ['CWE-78'] | ['CWE-78'] | oui |
| cmd_shell_true | ['CWE-78'] | ['CWE-78'] | oui |
| cmd_safe_list | [] | [] | oui |
| code_eval | ['CWE-94'] | ['CWE-94'] | oui |
| code_exec | ['CWE-94'] | ['CWE-94'] | oui |
| code_safe_literal | [] | [] | oui |
| deser_pickle | ['CWE-502'] | ['CWE-502'] | oui |
| deser_yaml | ['CWE-502'] | ['CWE-502'] | oui |
| deser_safe_json | [] | [] | oui |
| deser_safe_yaml | [] | [] | oui |
| hash_md5 | ['CWE-327'] | ['CWE-327'] | oui |
| hash_safe_sha256 | [] | [] | oui |
| tls_verify_false | ['CWE-295'] | ['CWE-295'] | oui |
| tls_safe | [] | [] | oui |
| secret_password | ['CWE-798'] | ['CWE-798'] | oui |
| secret_apikey_literal | ['CWE-798'] | ['CWE-798'] | oui |
| secret_env_safe | [] | [] | oui |
| secret_hf_token_yaml | ['CWE-798'] | ['CWE-798'] | oui |
| secret_env_ref_safe | [] | [] | oui |
