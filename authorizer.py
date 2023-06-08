import hmac
import hashlib
import re
import os
import base64
import ipaddress
import urllib3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def verify_webhook(data, hmac_header):
		# Calculate HMAC
    digest = hmac.new(os.environ.get('SECRET').encode('utf-8'), data, digestmod=hashlib.sha256)
    computed_hmac = digest.hexdigest()
    logger.debug(f"Computed hmac: {computed_hmac}")
    logger.debug(f"Received hmac: {hmac_header}")

    return hmac.compare_digest(computed_hmac, hmac_header)
    
def verify_whitelist(src_ip):
    for allowed in os.environ.get('WHITELIST').split(','):
        if ipaddress.ip_address(src_ip) in ipaddress.ip_network(allowed.strip()):
            return True
    return False

    
def lambda_handler(event, context):
    logger.debug(f"event: {json.dumps(event)}")
    logger.info(f"event body: {json.dumps(json.loads(event['body']))}")
    try:
        src_ip = event['headers']['x-forwarded-for']
    except KeyError:
        logger.error("Missing the x-forwarded-for header. Giving up...")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "message": "Missing x-forwarded-for header"
            }),
            "isBase64Encoded": "false"
        }
    try:
        signed_hmac = re.sub(r'^sha256=', '', event['headers']['x-hub-signature-256'])
    except KeyError:
        logger.error("Missing the signature header. Secret not present. Giving up...")
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "message": "Missing x-hub-signature-256 header"
            }),
            "isBase64Encoded": "false"
        }
        
    ip_check = verify_whitelist(src_ip)
    if ip_check:
        logger.info("ip allowed")
    else:
        logger.warning("ip blocked")
        return {
            "statusCode": 403,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "message": "Source IP address not whitelisted",
                "src_ip": src_ip
            }),
            "isBase64Encoded": "false"
        }
    verified = verify_webhook(event['body'].encode('utf-8'), signed_hmac)
    if not verified:
        logger.warning("Unauthorized")
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "message": "The signature in the embedded message does not match the calculated one.",
                "isAuthorized": verified
            }),
            "isBase64Encoded": "false"
        }

    # Do something with the webhook 
    logger.info("Authorized")
    http = urllib3.PoolManager()
    try:
        #Remove the headers that are generated due to secret usage
        del event['headers']['x-hub-signature-256']
        del event['headers']['x-hub-signature']
        logger.debug(f"event['headers]: {json.dumps(event['headers'])}")
        response = http.request('POST', os.environ.get('TARGET_URL'), headers=event['headers'], body=event['body'], timeout=7.0)
        logger.info(f"response status: {response.status}")
        
    except Exception as e:
        logger.error("send failed executing http.request: %s", str(e))

    logger.debug(f"response data: {response.data.decode('utf-8')}")
    logger.debug(f"response headers: {json.dumps(dict(response.headers))}")


    return {
        "statusCode": response.status,
        "headers": dict(response.headers),
        "body": response.data.decode('utf-8'),
        "isBase64Encoded": "false"
    }
  
