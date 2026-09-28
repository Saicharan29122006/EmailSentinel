import pandas as pd


def detect_high_volume_senders(df, threshold=5):
    """
    Detect senders whose email count is above the threshold.
    """

    sender_counts = (
        df["sender"]
        .value_counts()
        .reset_index()
    )

    sender_counts.columns = [
        "sender",
        "email_count"
    ]

    suspicious = sender_counts[
        sender_counts["email_count"] > threshold
    ].copy()

    suspicious["alert"] = "High Email Volume"

    return suspicious


def detect_high_volume_receivers(df, threshold=5):
    """
    Detect receivers receiving an unusually high
    number of emails.
    """

    receiver_counts = (
        df["receiver"]
        .value_counts()
        .reset_index()
    )

    receiver_counts.columns = [
        "receiver",
        "email_count"
    ]

    suspicious = receiver_counts[
        receiver_counts["email_count"] > threshold
    ].copy()

    suspicious["alert"] = "High Receiving Volume"

    return suspicious


def detect_unusual_pairs(df, threshold=3):
    """
    Detect sender-receiver pairs with unusually
    high communication frequency.
    """

    pairs = (
        df.groupby(
            ["sender", "receiver"]
        )
        .size()
        .reset_index(
            name="email_count"
        )
    )

    suspicious = pairs[
        pairs["email_count"] > threshold
    ].copy()

    suspicious["alert"] = (
        "Frequent Communication"
    )

    return suspicious


def generate_security_summary(df):
    """
    Generate a summary of email security indicators.
    """

    total_emails = len(df)

    unique_senders = (
        df["sender"].nunique()
    )

    unique_receivers = (
        df["receiver"].nunique()
    )

    high_volume_senders = (
        detect_high_volume_senders(df)
    )

    high_volume_receivers = (
        detect_high_volume_receivers(df)
    )

    unusual_pairs = (
        detect_unusual_pairs(df)
    )

    return {
        "total_emails": total_emails,
        "unique_senders": unique_senders,
        "unique_receivers": unique_receivers,
        "high_volume_senders":
            len(high_volume_senders),
        "high_volume_receivers":
            len(high_volume_receivers),
        "unusual_pairs":
            len(unusual_pairs)
    }


def calculate_risk_score(df):
    """
    Calculate an overall cybersecurity
    risk score from 0 to 100.
    """

    high_volume_senders = (
        detect_high_volume_senders(df)
    )

    high_volume_receivers = (
        detect_high_volume_receivers(df)
    )

    unusual_pairs = (
        detect_unusual_pairs(df)
    )

    score = 0

    score += (
        len(high_volume_senders) * 15
    )

    score += (
        len(high_volume_receivers) * 10
    )

    score += (
        len(unusual_pairs) * 10
    )

    # Maximum score is 100
    score = min(score, 100)

    if score >= 70:
        level = "HIGH"

    elif score >= 40:
        level = "MEDIUM"

    else:
        level = "LOW"

    return score, level


# ==================================================
# TESTING
# ==================================================

if __name__ == "__main__":

    file_path = "data/sample_emails.csv"

    df = pd.read_csv(file_path)

    print("\n==============================")
    print("    EMAIL SECURITY ANALYSIS")
    print("==============================")

    summary = generate_security_summary(df)

    print(
        f"\nTotal Emails: "
        f"{summary['total_emails']}"
    )

    print(
        f"Unique Senders: "
        f"{summary['unique_senders']}"
    )

    print(
        f"Unique Receivers: "
        f"{summary['unique_receivers']}"
    )

    print(
        f"High-Volume Senders: "
        f"{summary['high_volume_senders']}"
    )

    print(
        f"High-Volume Receivers: "
        f"{summary['high_volume_receivers']}"
    )

    print(
        f"Frequent Communication Pairs: "
        f"{summary['unusual_pairs']}"
    )

    risk_score, risk_level = (
        calculate_risk_score(df)
    )

    print(
        f"\nRisk Score: "
        f"{risk_score}/100"
    )

    print(
        f"Risk Level: "
        f"{risk_level}"
    )

    print("\nAnalysis completed successfully.")