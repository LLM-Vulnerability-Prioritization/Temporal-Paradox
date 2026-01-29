import pandas as pd
import numpy as np
from scipy import stats

# ----------------------------
# Config
# ----------------------------
PATH = "LASTX-NDSS-2026_LLM-PT-SDP-KCD-F1HARMONICMEAN.csv"
SEP = "\t"  # TSV

VALUE_COL = "F1SCORE_HARMONIC_MEAN"
CUTOFF_COL = "CUTOFF_STATUS"
GROUP_COLS = ["LLM", "PROMPTING_TECHNIQUE", "SSVC_DECISION_POINT"]

PRE_LABEL = "pre"
POST_LABEL = "post"


# ----------------------------
# Helpers
# ----------------------------
def cohen_d_independent(group1: pd.Series, group2: pd.Series) -> float:
    """
    Cohen's d for independent samples using pooled standard deviation.
    d = (mean1 - mean2) / pooled_sd

    Args:
        group1: First group (will be in numerator)
        group2: Second group (will be subtracted from group1)
    """
    n1, n2 = len(group1), len(group2)
    var1, var2 = group1.var(ddof=1), group2.var(ddof=1)

    # Pooled standard deviation
    pooled_sd = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))

    if pooled_sd == 0:
        return np.nan

    return (group1.mean() - group2.mean()) / pooled_sd


def mean_diff_ci_independent(group1: pd.Series, group2: pd.Series, alpha: float = 0.05):
    """
    CI for difference between two independent means using Welch's approach.
    Returns: (mean_diff, ci_lower, ci_upper) where mean_diff = mean(group1) - mean(group2)
    """
    n1, n2 = len(group1), len(group2)
    mean1, mean2 = group1.mean(), group2.mean()
    var1, var2 = group1.var(ddof=1), group2.var(ddof=1)

    # Standard error of difference
    se_diff = np.sqrt(var1/n1 + var2/n2)

    # Welch-Satterthwaite degrees of freedom
    df = (var1/n1 + var2/n2)**2 / ((var1/n1)**2/(n1-1) + (var2/n2)**2/(n2-1))

    tcrit = stats.t.ppf(1 - alpha / 2, df)
    mean_diff = mean1 - mean2

    return mean_diff, (mean_diff - tcrit * se_diff), (mean_diff + tcrit * se_diff)


# ----------------------------
# Load + clean
# ----------------------------
df = pd.read_csv(PATH, sep=SEP)

required = set(GROUP_COLS + [CUTOFF_COL, VALUE_COL])
missing = required - set(df.columns)
if missing:
    raise ValueError(f"Missing required columns: {sorted(missing)}")

# Normalize cutoff labels
df[CUTOFF_COL] = df[CUTOFF_COL].astype(str).str.strip().str.lower()

# Keep only pre/post rows
df = df[df[CUTOFF_COL].isin([PRE_LABEL, POST_LABEL])].copy()

# Ensure numeric values
df[VALUE_COL] = pd.to_numeric(df[VALUE_COL], errors="coerce")
df = df.dropna(subset=[VALUE_COL])

# Combined factor
df["LLM_PT_SDP"] = df[GROUP_COLS].astype(str).agg("_".join, axis=1)

# ----------------------------
# Data integrity checks
# ----------------------------
print("=" * 80)
print("DATA OVERVIEW")
print("=" * 80)
print(f"Dataset shape: {df.shape}")
print(f"Unique LLMs: {df['LLM'].nunique()}")
print(f"Unique Prompting Techniques: {df['PROMPTING_TECHNIQUE'].nunique()}")
print(f"Unique SSVC Decision Points: {df['SSVC_DECISION_POINT'].nunique()}")
print(f"Unique LLM-PT-SDP combinations: {df['LLM_PT_SDP'].nunique()}")

# Split into two independent groups
pre_group = df[df[CUTOFF_COL] == PRE_LABEL][VALUE_COL]
post_group = df[df[CUTOFF_COL] == POST_LABEL][VALUE_COL]

n_pre = len(pre_group)
n_post = len(post_group)

print("\n" + "=" * 80)
print("INDEPENDENT SAMPLES SUMMARY")
print("=" * 80)
print(f"Pre-cutoff vulnerabilities (n): {n_pre}")
print(f"Post-cutoff vulnerabilities (n): {n_post}")
print(f"Pre mean (SD):  {pre_group.mean():.4f} ({pre_group.std(ddof=1):.4f})")
print(f"Post mean (SD): {post_group.mean():.4f} ({post_group.std(ddof=1):.4f})")
print(f"Mean diff (post - pre): {post_group.mean() - pre_group.mean():.4f}")

# ----------------------------
# Independent samples t-test
# ----------------------------
print("\n" + "=" * 80)
print("INDEPENDENT SAMPLES T-TEST (Welch's)")
print("=" * 80)

# Welch's t-test: pass POST first, PRE second to get (post - pre) direction
t_stat, p_value = stats.ttest_ind(post_group, pre_group, equal_var=False)

# Cohen's d for independent samples: POST - PRE
d = cohen_d_independent(post_group, pre_group)
mean_diff, ci_lo, ci_hi = mean_diff_ci_independent(post_group, pre_group)

print(f"t-statistic (post - pre): {t_stat:.4f}")
print(f"p-value: {p_value:.10e}")
print(f"Mean diff (post - pre): {mean_diff:.4f}")
print(f"95% CI for mean diff: [{ci_lo:.4f}, {ci_hi:.4f}]")
print(f"Cohen's d (independent): {d:.4f}")

# Effect size interpretation
abs_d = abs(d)
if abs_d < 0.2:
    effect_interp = "negligible"
elif abs_d < 0.5:
    effect_interp = "small"
elif abs_d < 0.8:
    effect_interp = "medium"
else:
    effect_interp = "large"
print(f"Effect size interpretation: {effect_interp}")

# Interpretation
direction = "HIGHER" if mean_diff > 0 else "LOWER" if mean_diff < 0 else "EQUAL"
sig = "SIGNIFICANT" if p_value < 0.05 else "NOT SIGNIFICANT"
print(f"\nResult: {sig}. Post-cutoff F1 is {direction} than pre-cutoff (by post-pre).")
