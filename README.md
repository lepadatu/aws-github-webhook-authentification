# GitHub WebHooks Authentication Using AWS Lambda
A serverless way to authenticate github webhooks, primarily for usage with AWS private resources (e.g. private Jenkins instance) as an alternative to ngrok.

I will consider Jenkins running on ec2 as a typical example here for GitHub webhook consumer although the code is generic.

When running Jenkins in a private AWS subnet that does not accept inbound connections, working with GitHub webhooks becomes problematic, since the GitHub webhook cannot connect to Jenkins runing privately. The NAT gateway specifically forbids this while allowing Jenkins to initiate outbound connections in order to update or install plug-ins:

![Project in a spotlight](https://github.com/lepadatu/aws-github-webhook-authentification/assets/16731864/92de8a2a-2b7f-496e-a2a2-dcf68ab652fd)

The security measure put in place to protect Jenkins against inbound connections from the Internet prevents GitHub from accessing it. But we still want to use webhooks, right?

One option is to use ngrok-like tools, that have limitations in case of free variants (e.g. 500 calls/month plus several others).

The solution presented here de-couples the GitHub webhook authentication part from Jenkins and runs is in an AWS Lambda function. The capabilities of the lambda function are:

- GitHub webhook authentication
- Source IP filtering using `X-Forwarded-For` header
- Forwarding the webhook to the relevant target once IP-filtered and authenticated

The code hosted in [authorizer.py](authorizer.py) is purposed to run in a lambda function deployed in a VPC. This VPC does not need to coincide with Jenkins VPC as in the diagram below, but must be able to reach Jenkins instance in order to forward the webhook POST requests. As long as there is connectivity between lambda ENI and the service that processes the webhook (Jenkins), it should work.

![Project in the spotlight1](https://github.com/lepadatu/aws-github-webhook-authentification/assets/16731864/abf32bfa-7877-4e44-80a9-89488d836089)


The lambda functions requires 3 environment variables:
1. `SECRET` is the shared secret with GitHub webhook.
2. `TARGET_URL` is the target URL the lambda should forward the initial incoming POST request to, inside AWS VPC (in this particular case the Jenkins URL).
3. `WHITELIST` is a comma-separated list of CIDR ranges.

Since they contain sensitive information, it is highly recommended to use CMK (Customer-Managed Key)encryption in order to encrypt them. The key policy of the CMK can specify who can decrypt it:
https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk
https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption
https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html

Obviously, the lambda function will need to be able to decrypt the above environment variables.

In order to prevent abuse, it is recommended to limit concurrency as well.

# Limitations

The lambda function has been tested with `Python 3.9`.

Only `application/json` Github webhooks content type is supported.

# Connectivity Concerns
Q: How to connect to Jenkins server running in a private subnet? The design does not allow inbound connections from the Internet.

A: Using AWS Session Manager port forwarding. Simply forward Jenkins port. See the AWS blog post below for more details:
https://aws.amazon.com/blogs/aws/new-port-forwarding-using-aws-system-manager-sessions-manager/


# Design Considerations
Initially I have considered AWS API gateway as the best approach for the task together with proxy integration and lambda authorizer. In order to authenticate the webhook, one needs to access the payload in order to re-generate the HMAC digest. However, due to API Gateway limitations, the lambda authorizer cannot access the payload of the incoming request. 

Another viable option is to use AWS CloudFront and AWS WAF but this comes with increased costs: https://aws.amazon.com/blogs/compute/securing-lambda-function-urls-using-amazon-cognito-amazon-cloudfront-and-aws-waf/. Obviously IP filtering becomes obsolete in this case since it is handled by AWS WAF. But the issue in this case is the fact there is nothing to prevent users from accessing the function url directly but security by obscurity, since the url contains a long random string.

Unfortunately, the AWS WAF cannot yet protect AWS Lambda urls directly for now... one must use CloudFront in the middle.
