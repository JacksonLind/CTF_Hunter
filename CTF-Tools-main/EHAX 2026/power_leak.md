# Power Leak — Side-Channel Analysis

**CTF:** EH4X  
**Category:** Side-Channel Analysis  
**Author:** tanishfr  
**Flag:** `EHAX{5bec84ad039e23fcd51d331e662e27be15542ca83fd8ef4d6c5e5a8ad614a54d}`

---

## Challenge Overview

We're given a CSV file containing power traces collected while a device processed guesses for each digit of a secret PIN. The dataset is structured as:

```
position  (0–5)     — which digit of the PIN
guess     (0–9)     — the digit being tested
trace_num (0–19)    — 20 repetitions per guess
sample    (0–50)    — 51 power samples per trace
power_mW            — measured power consumption
```

This gives us `6 positions × 10 guesses × 20 traces × 51 samples = 61,200 rows`. The goal is to recover the 6-digit secret by identifying which guess causes a statistically distinguishable power signature at each position.

---

## Background: Power Analysis Attacks

Power analysis exploits the fact that electronic devices consume different amounts of power depending on the data they process. When a device computes operations on a secret value, the power consumption at each clock cycle leaks information about that value. This challenge is a textbook **Differential Power Analysis (DPA)** scenario.

---

## Methodology

### Step 1: Understanding the Data Structure

```python
import pandas as pd
df = pd.read_csv('power_traces.csv')
print(df['position'].unique())  # [0,1,2,3,4,5]
print(df['guess'].unique())     # [0,1,2,...,9]
print(df['trace_num'].unique()) # [0,1,...,19]
print(df['sample'].max())       # 50
```

### Step 2: Averaging Traces

For each `(position, guess)` combination, average all 20 traces across their 51 samples. This reduces noise and amplifies the signal of the correct digit — a standard DPA technique.

```python
avg_traces = df.groupby(['guess','sample'])['power_mW'].mean().unstack()
```

### Step 3: Visual Inspection

Plot the averaged trace for each guess at each position. The correct digit produces a trace with a noticeably higher spike at a specific sample compared to all other guesses.

### Step 4: Identifying the Correct Digit per Position

For each position, identify the guess whose averaged trace deviated most from the mean of all guesses — this is the statistical signature of the correct digit.

```python
overall_mean = avg_traces.mean(axis=0)
deviations   = ((avg_traces - overall_mean) ** 2).sum(axis=1)
best_guess   = deviations.idxmax()
```

Visual inspection of the zoomed-in charts confirmed the correct digit at each position:

| Position | Correct Digit | Observation |
|---|---|---|
| 0 | 7 | Clear spike above all others |
| 1 | 9 | Peaks highest |
| 2 | 2 | Stands out |
| 3 | 9 | Clear outlier |
| 4 | 6 | Highest peak |
| 5 | 3 | Correct digit |

---

## Solution

### Recovering the Secret

```python
secret = "792963"
```

### Computing the Flag

```python
import hashlib
secret = "792963"
flag = "EHAX{" + hashlib.sha256(secret.encode()).hexdigest() + "}"
# EHAX{5bec84ad039e23fcd51d331e662e27be15542ca83fd8ef4d6c5e5a8ad614a54d}
```

---

## Key Takeaways

- **Power analysis attacks** exploit the physical behaviour of hardware to leak secret information without breaking the cryptography mathematically.
- **Averaging multiple traces** per guess is essential — it cancels out random noise and amplifies the signal from the correct key.
- **Visual inspection of averaged traces** is often sufficient for simple PIN-style secrets: the correct digit produces a visually distinct spike.
- In real-world scenarios, countermeasures such as random delays, power balancing, and masking are used to defeat these attacks.

---

**Flag:** `EHAX{5bec84ad039e23fcd51d331e662e27be15542ca83fd8ef4d6c5e5a8ad614a54d}`
