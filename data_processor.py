import pandas as pd


REQUIRED_COLUMNS = [
    "email_id",
    "timestamp",
    "sender",
    "receiver",
    "subject"
]


def load_email_data(file_path):
    """
    Load email data from a CSV file.
    """

    df = pd.read_csv(file_path)

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {', '.join(missing_columns)}"
        )

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["sender", "receiver", "timestamp"]
    )

    return df


def get_top_senders(df, limit=10):
    """
    Return the most active email senders.
    """

    result = (
        df["sender"]
        .value_counts()
        .head(limit)
        .reset_index()
    )

    result.columns = ["email", "email_count"]

    return result


def get_top_receivers(df, limit=10):
    """
    Return the most active email receivers.
    """

    result = (
        df["receiver"]
        .value_counts()
        .head(limit)
        .reset_index()
    )

    result.columns = ["email", "email_count"]

    return result


def get_sender_receiver_pairs(df, limit=10):
    """
    Return the most frequent sender-receiver pairs.
    """

    result = (
        df.groupby(["sender", "receiver"])
        .size()
        .reset_index(name="email_count")
        .sort_values(
            "email_count",
            ascending=False
        )
        .head(limit)
    )

    return result


if __name__ == "__main__":

    file_path = "data/sample_emails.csv"

    data = load_email_data(file_path)

    print("\n==============================")
    print("       EMAIL SENTINEL")
    print("==============================")

    print("\nTOP SENDERS")
    print("------------------------------")
    print(get_top_senders(data).to_string(index=False))

    print("\nTOP RECEIVERS")
    print("------------------------------")
    print(get_top_receivers(data).to_string(index=False))

    print("\nTOP SENDER-RECEIVER PAIRS")
    print("------------------------------")
    print(
        get_sender_receiver_pairs(data)
        .to_string(index=False)
    )

    print("\n==============================")
    print("Analysis completed successfully.")
    print("==============================")