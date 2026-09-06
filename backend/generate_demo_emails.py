"""
Helper script to generate targeted demo emails for testing and evaluation:
  1. dummy_quishing_qr.eml       - Embedded QR code decoding to lookalike domain
  2. dummy_homoglyph.eml         - Unicode IDN Homoglyph attack (Cyrillic lookalike)
  3. dummy_vpn_cloud_origin.eml  - Routing from known commercial datacenter / VPN IP
"""

import io
import qrcode
from email.message import EmailMessage

def create_quishing_email():
    msg = EmailMessage()
    msg['Subject'] = 'Mandatory KYC Re-validation Required'
    msg['From'] = '"State Bank Support" <support@sbi-verifyportal.net>'
    msg['To'] = 'customer@example.com'
    msg['Date'] = 'Sun, 06 Sep 2026 11:30:00 +0530'
    msg['Message-ID'] = '<sbi-kyc-20260906@sbi-verifyportal.net>'
    msg['Reply-To'] = 'hacker-mailbox@gmail.com'
    msg['X-Mailer'] = 'SendBlaster 4.3'

    msg.add_header(
        'Received',
        'from mail-gw.sbi-verifyportal.net (mail-gw.sbi-verifyportal.net. [198.51.100.77]) '
        'by mx.victim-domain.com with ESMTPS id kyc99283; Sun, 06 Sep 2026 11:30:05 +0530'
    )

    html_content = """<!DOCTYPE html>
<html>
<body>
  <p>Dear Valued Customer,</p>
  <p>As per revised banking directives, your account profile requires mandatory KYC re-validation.</p>
  <p>Please scan the secure QR code below using your mobile phone camera to complete authentication:</p>
  <p><img src="cid:kyc_qr_code" alt="SBI KYC QR Code" width="200" height="200" /></p>
  <p>Failure to complete verification within 24 hours may lead to temporary restriction on outgoing UPI and NetBanking.</p>
  <p>Regards,<br>Customer Care & Compliance Services</p>
</body>
</html>"""

    msg.set_content('Dear Customer, Please scan the attached QR code to verify your KYC details immediately.')
    msg.add_alternative(html_content, subtype='html')

    # Generate real QR code pointing to lookalike domain
    qr_img = qrcode.make('http://bank0findia.co.in/sbi/kyc-login')
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    qr_bytes = buf.getvalue()

    msg.get_payload()[1].add_related(
        qr_bytes,
        maintype='image',
        subtype='png',
        cid='<kyc_qr_code>',
        filename='kyc_qr_code.png'
    )

    with open('data/test_emails/dummy_quishing_qr.eml', 'wb') as f:
        f.write(msg.as_bytes())
    print('Created data/test_emails/dummy_quishing_qr.eml')


def create_homoglyph_email():
    # Cyrillic small letter 'a' is \u0430, which looks identical to Latin 'a'
    # 'раypal.com' with Cyrillic 'а' decodes in punycode to 'xn--ypal-43d.com'
    homoglyph_domain = "р\u0430ypal.com"
    homoglyph_url = f"https://{homoglyph_domain}/security/signin?ref=account_hold"

    content = f"""Received: from dispatch-node.notification-system.org (dispatch-node.notification-system.org. [198.51.100.12])
        by mx.recipient-corp.com with ESMTPS id p88si992812qkc.14.2026.09.06.14.00.00
        for <user@recipient-corp.com>;
        Sun, 06 Sep 2026 14:00:00 -0400
From: "PayPal Account Security" <service@secure-notification-system.org>
To: user@recipient-corp.com
Subject: Suspicious Login Attempt Detected - Please Confirm Your Identity
Date: Sun, 06 Sep 2026 14:00:00 -0400
Message-ID: <sec-alert-88291@notification-system.org>
Reply-To: security-team@gmail.com
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; color: #333;">
  <p>Dear Customer,</p>
  <p>We detected an unrecognized device attempting to access your PayPal wallet from an unknown location.</p>
  <p>If this was not you, please secure your account immediately and confirm your login password and authorization PIN:</p>
  <p><a href="{homoglyph_url}">https://paypal.com/security/signin</a></p>
  <p>Sincerely,<br>PayPal Security & Risk Management</p>
</body>
</html>
"""
    with open('data/test_emails/dummy_homoglyph.eml', 'w', encoding='utf-8') as f:
        f.write(content)
    print('Created data/test_emails/dummy_homoglyph.eml')


def create_vpn_cloud_origin_email():
    # DigitalOcean ASN AS14061 IP: 167.99.160.1
    content = """Received: from mail-relay.inbound.mx.google.com (mail-relay.inbound.mx.google.com. [209.85.212.49])
        by mx.victim-corp.com with ESMTPS id o10si8606403qkc.101.2026.09.06.08.31.25
        for <victim@victim-corp.com>;
        Sun, 06 Sep 2026 08:31:25 -0400
Received: from unmanaged-droplet.digitalocean.com (unmanaged-droplet.digitalocean.com. [167.99.160.1])
        by mail-relay.inbound.mx.google.com with SMTP id xyz789;
        Sun, 06 Sep 2026 08:30:10 -0400
From: "Corporate IT Support" <helpdesk@corporate-internal.net>
To: victim@victim-corp.com
Subject: Employee Software License Update Notification
Date: Sun, 06 Sep 2026 08:30:00 -0400
Message-ID: <lic-notice-20260906@digitalocean.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Team,

Please be advised that internal software licenses have been renewed.
You can review the updated entitlement catalog from our internal portal:

http://corporate-internal.net/license-catalog

Thank you,
IT Desktop Support Team
"""
    with open('data/test_emails/dummy_vpn_cloud_origin.eml', 'w', encoding='utf-8') as f:
        f.write(content)
    print('Created data/test_emails/dummy_vpn_cloud_origin.eml')


if __name__ == '__main__':
    create_quishing_email()
    create_homoglyph_email()
    create_vpn_cloud_origin_email()
    print('All demo emails generated successfully.')
