import smtplib
import os
from email.message import EmailMessage

def send_report_email(recipient_email, repo_name, pdf_bytes):
    # Dynamically read each time so updates to .env take immediate effect without server restart
    sender = os.getenv("GMAIL_SENDER")
    password = os.getenv("GMAIL_APP_PASSWORD")
    
    if not sender or not password:
        raise ValueError("Gmail SMTP credentials (GMAIL_SENDER, GMAIL_APP_PASSWORD) are not configured in your .env file!")

    msg = EmailMessage()
    msg['Subject'] = f"🛡️ HackHelix Vulnerability Report for {repo_name}"
    msg['From'] = sender
    msg['To'] = recipient_email

    msg.set_content(
        f"Hello,\n\n"
        f"Please find attached the automated HackHelix Vulnerability Report for your repository: {repo_name}.\n\n"
        f"This report highlights critical dependencies alongside actionable native code fixes generated securely by our platform.\n\n"
        f"Stay Secure!\n- The HackHelix Engine"
    )

    msg.add_attachment(
        bytes(pdf_bytes),
        maintype='application',
        subtype='pdf',
        filename=f"HackHelix_Report_{repo_name}.pdf"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.send_message(msg)
