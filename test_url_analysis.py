from services.url_analyser import analyse_urls


test_text = """
Legitimate:
https://www.example.com/project

Suspicious:
http://192.168.1.20/login/verify-account

Shortened:
https://bit.ly/secure-login

Long subdomain:
http://paypal.security.verify.account.example.xyz/login
"""


results = analyse_urls(
    test_text
)


for result in results:
    print("=" * 75)
    print("URL:", result["url"])
    print("Hostname:", result["hostname"])
    print("Risk level:", result["risk_level"])
    print("Risk score:", result["risk_score"])
    print("Entropy:", result["entropy"])
    print("Suspicious:", result["suspicious"])

    print("Indicators:")

    for indicator in result["indicators"]:
        print("-", indicator)
