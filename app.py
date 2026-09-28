import streamlit as st
import pandas as pd

from src.data_processor import (
    load_email_data,
    get_top_senders,
    get_top_receivers,
    get_sender_receiver_pairs
)

from src.security import (
    generate_security_summary,
    detect_high_volume_senders,
    detect_high_volume_receivers,
    detect_unusual_pairs,
    calculate_risk_score
)


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="EmailSentinel",
    page_icon="🛡️",
    layout="wide"
)


# ==================================================
# HEADER
# ==================================================

st.title("🛡️ EmailSentinel")

st.subheader(
    "Email Sender & Receiver Security Monitoring System"
)

st.markdown(
    "Analyze email communication patterns and identify "
    "potentially unusual activity."
)


# ==================================================
# DATA SOURCE
# ==================================================

st.sidebar.header("📁 Data Source")

uploaded_file = st.sidebar.file_uploader(
    "Upload Email CSV",
    type=["csv"]
)


# ==================================================
# LOAD DATA
# ==================================================

if uploaded_file is not None:

    try:

        df = pd.read_csv(uploaded_file)

        required_columns = [
            "email_id",
            "timestamp",
            "sender",
            "receiver",
            "subject"
        ]

        missing_columns = [
            column
            for column in required_columns
            if column not in df.columns
        ]

        if missing_columns:

            st.error(
                "Invalid CSV file. Missing columns: "
                + ", ".join(missing_columns)
            )

            st.stop()

        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

        df = df.dropna(
            subset=[
                "sender",
                "receiver",
                "timestamp"
            ]
        )

        st.sidebar.success(
            "Uploaded dataset loaded successfully."
        )

    except Exception as error:

        st.error(
            f"Unable to process uploaded file: {error}"
        )

        st.stop()

else:

    DATA_FILE = "data/sample_emails.csv"

    try:

        df = load_email_data(DATA_FILE)

        st.sidebar.info(
            "Using built-in sample dataset."
        )

    except Exception as error:

        st.error(
            f"Unable to load sample dataset: {error}"
        )

        st.stop()


# ==================================================
# DATASET INFORMATION
# ==================================================

st.sidebar.divider()

st.sidebar.metric(
    "Total Records",
    len(df)
)

st.sidebar.metric(
    "Unique Senders",
    df["sender"].nunique()
)

st.sidebar.metric(
    "Unique Receivers",
    df["receiver"].nunique()
)


st.divider()


# ==================================================
# SECURITY SUMMARY
# ==================================================

summary = generate_security_summary(df)

risk_score, risk_level = calculate_risk_score(df)


# ==================================================
# KPI CARDS
# ==================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "📧 Total Emails",
        summary["total_emails"]
    )


with col2:

    st.metric(
        "📤 Unique Senders",
        summary["unique_senders"]
    )


with col3:

    st.metric(
        "📥 Unique Receivers",
        summary["unique_receivers"]
    )


with col4:

    st.metric(
        "🚨 Security Indicators",
        (
            summary["high_volume_senders"]
            + summary["high_volume_receivers"]
            + summary["unusual_pairs"]
        )
    )


st.divider()


# ==================================================
# RISK SCORE
# ==================================================

st.subheader("🛡️ Cybersecurity Risk Assessment")


risk_col1, risk_col2 = st.columns([1, 2])


with risk_col1:

    st.metric(
        "Risk Score",
        f"{risk_score}/100"
    )


with risk_col2:

    if risk_level == "HIGH":

        st.error(
            "🔴 HIGH RISK — "
            "Multiple unusual email activity indicators detected."
        )

    elif risk_level == "MEDIUM":

        st.warning(
            "🟠 MEDIUM RISK — "
            "Some unusual email activity indicators detected."
        )

    else:

        st.success(
            "🟢 LOW RISK — "
            "No significant unusual activity detected."
        )


st.divider()


# ==================================================
# TOP SENDERS & RECEIVERS
# ==================================================

left_column, right_column = st.columns(2)


with left_column:

    st.subheader("📤 Top Email Senders")

    top_senders = get_top_senders(df, 10)

    st.bar_chart(
        top_senders.set_index("email")["email_count"],
        use_container_width=True
    )


with right_column:

    st.subheader("📥 Top Email Receivers")

    top_receivers = get_top_receivers(df, 10)

    st.bar_chart(
        top_receivers.set_index("email")["email_count"],
        use_container_width=True
    )


st.divider()


# ==================================================
# EMAIL ACTIVITY OVER TIME
# ==================================================

st.subheader("📈 Email Activity Over Time")


daily_activity = (
    df.groupby(df["timestamp"].dt.date)
    .size()
    .reset_index(name="email_count")
)

daily_activity.columns = [
    "date",
    "email_count"
]


st.line_chart(
    daily_activity.set_index("date")["email_count"],
    use_container_width=True
)


st.divider()


# ==================================================
# COMMUNICATION PAIRS
# ==================================================

st.subheader(
    "🔄 Top Sender–Receiver Communication"
)

pairs = get_sender_receiver_pairs(df, 10)

st.dataframe(
    pairs,
    use_container_width=True,
    hide_index=True
)


st.divider()


# ==================================================
# SECURITY ANALYSIS
# ==================================================

st.subheader("🚨 Security Analysis")


high_volume_senders = (
    detect_high_volume_senders(df)
)

high_volume_receivers = (
    detect_high_volume_receivers(df)
)

unusual_pairs = (
    detect_unusual_pairs(df)
)


security_col1, security_col2, security_col3 = (
    st.columns(3)
)


with security_col1:

    st.metric(
        "⚠️ High-Volume Senders",
        len(high_volume_senders)
    )


with security_col2:

    st.metric(
        "⚠️ High-Volume Receivers",
        len(high_volume_receivers)
    )


with security_col3:

    st.metric(
        "🔄 Frequent Communication",
        len(unusual_pairs)
    )


st.divider()


# ==================================================
# SECURITY ALERTS
# ==================================================

st.subheader(
    "🔎 Detected Security Indicators"
)


if not high_volume_senders.empty:

    st.warning(
        "⚠️ High-volume email senders detected."
    )

    st.dataframe(
        high_volume_senders,
        use_container_width=True,
        hide_index=True
    )


if not high_volume_receivers.empty:

    st.warning(
        "⚠️ High-volume email receivers detected."
    )

    st.dataframe(
        high_volume_receivers,
        use_container_width=True,
        hide_index=True
    )


if not unusual_pairs.empty:

    st.info(
        "🔄 Frequent sender-receiver communication detected."
    )

    st.dataframe(
        unusual_pairs,
        use_container_width=True,
        hide_index=True
    )


if (
    high_volume_senders.empty
    and high_volume_receivers.empty
    and unusual_pairs.empty
):

    st.success(
        "✅ No security indicators detected."
    )


# ==================================================
# DATA PREVIEW
# ==================================================

st.divider()

with st.expander("📄 View Email Dataset"):

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )


# ==================================================
# ABOUT
# ==================================================

st.divider()

with st.expander("ℹ️ About EmailSentinel"):

    st.write(
        """
        EmailSentinel is an Information and Cyber Security
        micro-project designed to monitor email communication
        patterns.

        The system analyzes email metadata to identify:

        • Top email senders
        • Top email receivers
        • Frequent communication pairs
        • High-volume email activity
        • Potentially unusual communication patterns
        • Overall cybersecurity risk level

        High email volume does not automatically indicate
        malicious activity. These indicators should be
        investigated further by a security analyst.
        """
    )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "EmailSentinel | Information & Cyber Security Micro Project"
)