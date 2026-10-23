# email_service.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

load_dotenv()


class EmailService:
    # ─────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────
    @staticmethod
    def send_welcome_email(user_email: str, full_name: str):
        print(f"\n📧 Sending welcome email to: {user_email}")
        subject = "Welcome to TrueSite - Your Security Partner"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Welcome to TrueSite</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #1e3a8a, #0891b2); color: white; padding: 30px; text-align: center; }}
                .content {{ padding: 30px; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 5px; }}
                .footer {{ background: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h1>🛡️ Welcome to TrueSite</h1></div>
                <div class="content">
                    <h2>Hello {full_name}!</h2>
                    <p>Thank you for joining TrueSite — your AI-powered phishing detection platform.</p>
                    <p>You get <strong>5 free analyses per day</strong> to start with.</p>
                    <center><a href="http://localhost:5173" class="button">Start Analyzing →</a></center>
                </div>
                <div class="footer">
                    <p>TrueSite - University of Technology and Applied Sciences</p>
                </div>
            </div>
        </body>
        </html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_verification_email(user_email: str, full_name: str, verification_token: str):
        """Send email verification link to a newly registered user."""
        verify_url = f"http://localhost:5173/verify-email?token={verification_token}"
        subject = "Verify your TrueSite account"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Verify your TrueSite account</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #1e3a8a, #0891b2); color: white; padding: 30px; text-align: center; }}
                .content {{ padding: 30px; }}
                .button {{ display: inline-block; padding: 14px 28px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; }}
                .warning {{ background: #fef3c7; padding: 15px; margin: 20px 0; border-left: 4px solid #f59e0b; font-size: 14px; }}
                .footer {{ background: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; color: #666; }}
                .link-box {{ background: #f3f4f6; padding: 12px; border-radius: 5px; word-break: break-all; font-family: monospace; font-size: 12px; color: #1e3a8a; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h1>🛡️ Verify Your Email</h1></div>
                <div class="content">
                    <h2>Hello {full_name}!</h2>
                    <p>Thank you for signing up for TrueSite. Click the button below to verify your email address and activate your account.</p>
                    <center><a href="{verify_url}" class="button">Verify Email Address →</a></center>
                    <div class="warning">
                        <strong>⏱️ This link expires in 24 hours.</strong><br>
                        If it expires, you'll need to register again with the same email.
                    </div>
                    <p style="font-size: 13px; color: #666; margin-top: 30px;">
                        If the button doesn't work, copy and paste this link into your browser:
                    </p>
                    <div class="link-box">{verify_url}</div>
                    <p style="font-size: 13px; color: #666; margin-top: 20px;">
                        If you didn't create a TrueSite account, you can safely ignore this email.
                    </p>
                </div>
                <div class="footer">
                    <p>TrueSite - University of Technology and Applied Sciences</p>
                </div>
            </div>
        </body>
        </html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_password_reset_email(user_email: str, full_name: str, reset_token: str):
        reset_url = f"http://localhost:5173/reset-password?token={reset_token}&email={user_email}"
        subject = "Password Reset Request - TrueSite"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Reset Your Password</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #dc2626, #ea580c); color: white; padding: 30px; text-align: center; }}
                .content {{ padding: 30px; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 5px; }}
                .warning {{ background: #fef3c7; padding: 15px; margin: 20px 0; border-left: 4px solid #f59e0b; }}
                .footer {{ background: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h1>🔐 Password Reset Request</h1></div>
                <div class="content">
                    <h2>Hello {full_name}!</h2>
                    <p>We received a request to reset your TrueSite account password.</p>
                    <div class="warning">
                        <strong>⚠️ Didn't request this?</strong> You can safely ignore this email.
                    </div>
                    <center><a href="{reset_url}" class="button">Reset Your Password →</a></center>
                    <p>This link will expire in <strong>1 hour</strong> for security reasons.</p>
                </div>
                <div class="footer">
                    <p>TrueSite - University of Technology and Applied Sciences</p>
                </div>
            </div>
        </body>
        </html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_analysis_alert(user_email: str, full_name: str, url: str, result: str,
                            confidence: float, risk_score: float):
        if result.lower() not in ('suspicious', 'scam', 'phishing'):
            return True
        subject = f"⚠️ Security Alert: {result.upper()} Website Detected"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Security Alert</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #dc2626, #991b1b); color: white; padding: 30px; text-align: center; }}
                .content {{ padding: 30px; }}
                .alert-box {{ background: #fee2e2; padding: 15px; margin: 20px 0; border-left: 4px solid #dc2626; }}
                .url-box {{ background: #f3f4f6; padding: 12px; border-radius: 5px; word-break: break-all; font-family: monospace; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 5px; }}
                .footer {{ background: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h1>⚠️ Security Alert</h1><p>Potential Threat Detected</p></div>
                <div class="content">
                    <h2>Hello {full_name}!</h2>
                    <div class="alert-box">
                        <strong>🚨 Alert: Potential {result.upper()} Website Detected</strong>
                    </div>
                    <p>Our AI analysis system has flagged a URL as potentially dangerous:</p>
                    <div class="url-box">{url}</div>
                    <div class="alert-box">
                        <strong>Analysis Details:</strong><br>
                        Result: {result.upper()}<br>
                        Confidence: {int(confidence * 100)}%<br>
                        Risk Score: {int(risk_score * 100)}%
                    </div>
                    <center><a href="http://localhost:5173" class="button">View Full Analysis →</a></center>
                </div>
                <div class="footer">
                    <p>TrueSite - University of Technology and Applied Sciences</p>
                </div>
            </div>
        </body>
        </html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_password_change_confirmation(user_email: str, full_name: str):
        subject = "Password Changed Successfully - TrueSite"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Password Changed</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 30px; text-align: center; }}
                .content {{ padding: 30px; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 5px; }}
                .footer {{ background: #f3f4f6; padding: 20px; text-align: center; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h1>✅ Password Changed Successfully</h1></div>
                <div class="content">
                    <h2>Hello {full_name}!</h2>
                    <p>Your TrueSite account password has been successfully changed.</p>
                    <p>If you did not make this change, please contact our support team immediately.</p>
                    <center><a href="http://localhost:5173" class="button">Go to TrueSite →</a></center>
                </div>
                <div class="footer">
                    <p>TrueSite - University of Technology and Applied Sciences</p>
                </div>
            </div>
        </body>
        </html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    # ─────────────────────────────────────────────────────────────────────
    # Internal SMTP sender
    # ─────────────────────────────────────────────────────────────────────
    @staticmethod
    def _send_email(to_email: str, subject: str, html_content: str):
        try:
            smtp_server = os.getenv("MAIL_SERVER", "smtp.gmail.com")
            smtp_port   = int(os.getenv("MAIL_PORT", "587"))
            username    = os.getenv("MAIL_USERNAME")
            password    = os.getenv("MAIL_PASSWORD")
            from_email  = os.getenv("MAIL_FROM") or username

            if not username or not password:
                print(f"⚠️  Email credentials missing (MAIL_USERNAME/MAIL_PASSWORD).")
                print(f"   Would have sent to {to_email}: {subject}")
                return False

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From']    = from_email
            msg['To']      = to_email
            msg.attach(MIMEText(html_content, 'html'))

            server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()

            print(f"✅ Email sent successfully to {to_email} ({subject})")
            return True

        except Exception as e:
            print(f"❌ Failed to send email to {to_email}: {e}")
            return False