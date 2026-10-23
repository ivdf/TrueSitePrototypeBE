# email_service.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Centralized frontend URL
FRONTEND_URL = "https://truesiteprototypefe.pages.dev"
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
# This MUST be an email you verified in the Brevo dashboard
MAIL_FROM = os.getenv("MAIL_FROM") 
MAIL_FROM_NAME = "TrueSite Security"

class EmailService:
    # ─────────────────────────────────────────────────────────────────────
    # Internal Brevo API Sender
    # ─────────────────────────────────────────────────────────────────────
    @staticmethod
    def _send_email(to_email: str, subject: str, html_content: str):
        if not BREVO_API_KEY or not MAIL_FROM:
            print("⚠️ Brevo API Key or MAIL_FROM missing. Email not sent.")
            return False

        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json"
        }
        payload = {
            "sender": {"name": MAIL_FROM_NAME, "email": MAIL_FROM},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": html_content
        }

        try:
            print(f"📧 Sending email to {to_email} via Brevo API...")
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code in [200, 201, 202]:
                print(f"✅ Email sent successfully to {to_email}")
                return True
            else:
                print(f"❌ Brevo Error ({response.status_code}): {response.text}")
                return False
        except Exception as e:
            print(f"❌ Failed to connect to Brevo: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────
    # Public API (Unchanged methods, just using the new _send_email)
    # ─────────────────────────────────────────────────────────────────────
    @staticmethod
    def send_welcome_email(user_email: str, full_name: str):
        subject = "Welcome to TrueSite - Your Security Partner"
        html_content = f"""
        <!DOCTYPE html><html><body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1e3a8a;">Welcome to TrueSite, {full_name}!</h2>
            <p>Thank you for joining TrueSite — your AI-powered phishing detection platform.</p>
            <p>You get <strong>5 free analyses per day</strong> to start with.</p>
            <a href="{FRONTEND_URL}" style="display: inline-block; padding: 12px 24px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px;">Start Analyzing →</a>
        </div>
        </body></html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_verification_email(user_email: str, full_name: str, verification_token: str):
        verify_url = f"{FRONTEND_URL}/verify-email?token={verification_token}"
        subject = "Verify your TrueSite account"
        html_content = f"""
        <!DOCTYPE html><html><body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1e3a8a;">Verify Your Email</h2>
            <p>Hello {full_name},</p>
            <p>Click the button below to verify your email and activate your account.</p>
            <a href="{verify_url}" style="display: inline-block; padding: 14px 28px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0;">Verify Email Address →</a>
            <p style="font-size: 12px; color: #666;">If the button doesn't work, copy this link: <br>{verify_url}</p>
            <p style="font-size: 12px; color: #999;">This link expires in 24 hours.</p>
        </div>
        </body></html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_password_reset_email(user_email: str, full_name: str, reset_token: str):
        reset_url = f"{FRONTEND_URL}/reset-password?token={reset_token}&email={user_email}"
        subject = "Password Reset Request - TrueSite"
        html_content = f"""
        <!DOCTYPE html><html><body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #dc2626;">Password Reset Request</h2>
            <p>Hello {full_name},</p>
            <p>We received a request to reset your TrueSite password.</p>
            <a href="{reset_url}" style="display: inline-block; padding: 12px 24px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0;">Reset Your Password →</a>
            <p style="font-size: 12px; color: #666;">This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
        </div>
        </body></html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_analysis_alert(user_email: str, full_name: str, url: str, result: str, confidence: float, risk_score: float):
        if result.lower() not in ('suspicious', 'scam', 'phishing'):
            return True
        subject = f"⚠️ Security Alert: {result.upper()} Website Detected"
        html_content = f"""
        <!DOCTYPE html><html><body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #dc2626;">⚠️ Security Alert</h2>
            <p>Hello {full_name},</p>
            <p>TrueSite flagged a potentially dangerous URL:</p>
            <p style="background-color: #f3f4f6; padding: 10px; border-radius: 4px; font-family: monospace;">{url}</p>
            <p><strong>Result:</strong> {result.upper()}<br>
               <strong>Confidence:</strong> {int(confidence * 100)}%<br>
               <strong>Risk Score:</strong> {int(risk_score * 100)}%</p>
            <a href="{FRONTEND_URL}" style="display: inline-block; padding: 12px 24px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px;">View Details →</a>
        </div>
        </body></html>
        """
        return EmailService._send_email(user_email, subject, html_content)

    @staticmethod
    def send_password_change_confirmation(user_email: str, full_name: str):
        subject = "Password Changed Successfully - TrueSite"
        html_content = f"""
        <!DOCTYPE html><html><body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #10b981;">✅ Password Changed Successfully</h2>
            <p>Hello {full_name},</p>
            <p>Your TrueSite account password has been successfully changed.</p>
            <p style="font-size: 12px; color: #666;">If you did not make this change, please contact support immediately.</p>
        </div>
        </body></html>
        """
        return EmailService._send_email(user_email, subject, html_content)
