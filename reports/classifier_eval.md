# Classifier eval

Dataset: verazuo/jailbreak_llms 2023_05_07 (MIT). Stratified 80/20 split, seed 42.
Train 4904, held-out test 1227 (130 positives). Threshold 0.5.

| scorer | precision | recall | F1 | confusion matrix [[TN, FP], [FN, TP]] |
|---|---|---|---|---|
| classifier | 0.6875 | 0.8462 | 0.7586 | [[1047, 50], [20, 110]] |
| rules_only | 0.2582 | 0.5462 | 0.3506 | [[893, 204], [59, 71]] |
| rules_plus_classifier | 0.3343 | 0.9 | 0.4875 | [[864, 233], [13, 117]] |

Pure-Python scorer vs sklearn max |diff| on test set: 2.01e-09.

Caveat: this dataset labels *jailbreaks*. Its 'regular' class contains hundreds of prompt templates that start with 'Ignore all previous instructions...' (AIPRM style). The rules flag those on purpose, so the rules' 'false positives' here are mostly instruction overrides the dataset does not count as jailbreaks. See reports/redteam.md for the injection-specific suite.
