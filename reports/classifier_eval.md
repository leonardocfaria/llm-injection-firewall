# Classifier eval

Dataset: verazuo/jailbreak_llms 2023_05_07 (MIT). Stratified 80/20 split, seed 42.
Train 4904, held-out test 1227 (130 positives). Threshold 0.5.

| scorer | precision | recall | F1 | confusion matrix [[TN, FP], [FN, TP]] |
|---|---|---|---|---|
| classifier | 0.6875 | 0.8462 | 0.7586 | [[1047, 50], [20, 110]] |
| rules_only | 0.2624 | 0.5308 | 0.3511 | [[903, 194], [61, 69]] |
| runtime_policy (rules + classifier) | 0.3451 | 0.9 | 0.4989 | [[875, 222], [13, 117]] |

Pure-Python scorer vs sklearn max |diff| on test set: 2.01e-09.

Caveat: this dataset labels *jailbreaks*. Its 'regular' class contains hundreds of prompt templates that start with 'Ignore all previous instructions...' (AIPRM style). The rules flag those on purpose, so the rules' 'false positives' here are mostly instruction overrides the dataset does not count as jailbreaks. See reports/redteam.md for the injection-specific suite.
