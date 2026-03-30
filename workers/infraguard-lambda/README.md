# InfraGuard Edge Lambda

Lightweight AWS Lambda function that acts as an edge reverse proxy, providing domain fronting through AWS CloudFront or Lambda Function URLs.

## Architecture

```
Internet → [CloudFront / Lambda URL] → [This Lambda] → [InfraGuard Server] → [C2 Teamserver]
```

From a network observer's perspective, traffic goes to AWS IPs -- your actual server is never exposed.

## Deployment Options

### Option 1: Lambda Function URL (simplest)

A standalone HTTPS endpoint -- no CloudFront or API Gateway needed.

```bash
cd workers/infraguard-lambda

# Deploy with SAM CLI
sam build
sam deploy --guided \
  --parameter-overrides \
    InfraGuardBackend=https://your-server:443 \
    AllowedHosts=cdn.example.com \
    BlockedCountries=CN,RU,KP \
    HostMap=cdn.example.com:code.jquery.com
```

The output gives you a Function URL like `https://abc123.lambda-url.us-east-1.on.aws/` -- point your DNS CNAME to it.

### Option 2: CloudFront + Lambda@Edge

For full CDN caching and edge distribution:

1. Deploy the Lambda to `us-east-1` (required for Lambda@Edge)
2. Create a CloudFront distribution with the Lambda as origin-request trigger
3. Add your domain as a CloudFront alternate domain name (CNAME)

```bash
# Package and deploy
zip handler.zip handler.py
aws lambda create-function \
  --function-name infraguard-edge \
  --runtime python3.12 \
  --handler handler.handler \
  --zip-file fileb://handler.zip \
  --role arn:aws:iam::YOUR_ACCOUNT:role/lambda-edge-role \
  --region us-east-1 \
  --environment "Variables={INFRAGUARD_BACKEND=https://your-server:443,ALLOWED_HOSTS=cdn.example.com}"
```

### Option 3: API Gateway + Lambda

```bash
sam build
sam deploy --guided
```

Uses the API Gateway HTTP API endpoint as the proxy URL.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `INFRAGUARD_BACKEND` | Yes | InfraGuard server URL |
| `ALLOWED_HOSTS` | No | Comma-separated allowed Host headers |
| `BLOCKED_COUNTRIES` | No | ISO country codes to block at edge |
| `HOST_MAP` | No | Host rewriting (e.g., `aws-domain:c2-profile-host`) |

## Features

- **Zero dependencies** -- uses only Python stdlib (`urllib.request`, `ssl`, `json`)
- **Dual format support** -- handles both Lambda Function URL and Lambda@Edge event formats
- **TLS passthrough** -- accepts self-signed certs from InfraGuard (`verify=False`)
- **Header sanitization** -- strips AWS internal headers (`x-amz-*`) before forwarding
- **Client IP injection** -- `X-Real-IP` and `X-Forwarded-For` with the real source IP

## OPSEC Notes

- Lambda@Edge runs in AWS edge locations worldwide -- lowest latency to targets
- Function URLs use AWS-owned TLS certs -- no need to bring your own
- CloudFront distributions use `*.cloudfront.net` domains by default -- hard to attribute
- Add a custom domain via CloudFront alternate domain + ACM certificate for better cover
- Use `waf` rules on CloudFront to add additional filtering at the AWS edge

## Local Testing

```bash
# Test with a mock event
python3 -c "
from handler import handler
event = {
    'requestContext': {'http': {'method': 'GET', 'path': '/test', 'sourceIp': '1.2.3.4'}},
    'headers': {'host': 'cdn.example.com'},
    'rawQueryString': '',
}
import os
os.environ['INFRAGUARD_BACKEND'] = 'https://httpbin.org'
os.environ['ALLOWED_HOSTS'] = 'cdn.example.com'
print(handler(event, None))
"
```
