import os

# Create a realistic-looking fake email
fake_email_content = """Received: from mail-db1-f49.google.com (mail-db1-f49.google.com. [209.85.212.49])
        by mx.google.com with ESMTPS id o10si8606403qkc.101.2023.10.15.08.31.25
        for <victim@example.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 15 Oct 2023 08:31:25 -0700 (PDT)
Received: from fake-server.phish.com (fake-server.phish.com. [192.168.1.1])
        by mail-db1-f49.google.com with SMTP id xyz123;
        Sun, 15 Oct 2023 08:30:00 -0700 (PDT)
From: "IT Support" <admin@bankofindia-secure.com>
To: victim@example.com
Reply-To: hacker@gmail.com
Subject: URGENT: Your Account Has Been Suspended
Date: Sun, 15 Oct 2023 08:30:00 -0700
Message-ID: <1234567890@fake-server.phish.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear User,

Your account has been temporarily suspended due to suspicious login attempts.
Please click the link below to verify your identity immediately:

http://bank0findia.co.in/verify

Failure to do so will result in permanent account closure.

Thanks,
IT Support
"""

output_path = os.path.join(os.path.dirname(__file__), "data", "test_emails", "dummy_phishing_1.eml")

os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, "wb") as f:
    f.write(fake_email_content.encode('utf-8'))

print(f"Dummy email created successfully at: {output_path}")
