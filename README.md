# aws-github-webhook-authentification
A serverless way to authenticate github webhooks, primarily for usage with AWS private resources (e.g. private Jenkins instance) as an alternative to ngrok.

I will consider Jenkins running on ec2 as a typical example here for GitHub webhook consumer although the code is generic.

When running Jenkins in a private AWS subnet that does not accept inbound connections, working with GitHub webhooks becomes problematic, since the GitHub webhook cannot connect to Jenkins runing privately. The NAT gateway specifically forbids this while allowing Jenkins to initiate outbound connections in order to update or install plug-ins:

![Project in a spotlight](https://github.com/lepadatu/aws-github-webhook-authentification/assets/16731864/92de8a2a-2b7f-496e-a2a2-dcf68ab652fd)

The security measure put in place to protect Jenkins against inbound connections from the Internet prevents GitHub from accessing it. But we still want to use webhooks, right?

One option is to use ngrok-like tools, that have limitations in case of free variants (e.g. 500 calls/month plus several others).

The solution presented here de-couples the GitHub webhook authentication part from Jenkins and runs is in an AWS Lambda function. The capabilities of the lambda function are:

- GitHub webhook authentication
- Source IP filtering using X-Forwarded-For header
- Forwarding the webhook to the relevant target once IP-filtered and authenticated

The code hosted in [authorizer.py](authorizer.py) is purposed to run in a lambda function deployed in a VPC. This VPC does not need to coincide with Jenkins VPC as in the diagram below, but must be able to reach Jenkins instance in order to forward the webhook POST requests. As long as there is connectivity between lambda ENI and the service that processes the webhook (Jenkins), it should work.

![Project in the spotlight 2](https://github.com/lepadatu/aws-github-webhook-authentification/assets/16731864/741fd950-0230-434a-936e-08eddec68673)

The lambda functions requires 3 environment variables:
1. `SECRET` is the shared secret with GitHub webhook.
2. `TARGET_URL` is the target URL the lambda should forward the initial POST request to, inside AWS VPC.
3. `WHITELIST` is a comma-separated list of CIDR ranges.

Since they contain sensitive information, it is highly recommended to use CMK (Customer-Managed Key)encryption in order to encrypt them. The key policy of the CMK can specify who can decrypt it:
https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk
https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption
https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
Obviously, the lambda function will need to be able to decrypt the above environment variables.

In order to prevent abuse, it is recommended to limit concurrency as well.

The lambda function has been tested with `Python 3.9`.

Only json Github webhooks are supported.

# Design Considerations
Initially I have considered AWS API gateway as the best approach for the task together with proxy integration and lambda authorizer. In order to authenticate the webhook, one needs to access the payload in order to compute the HMAC signature. However, due to API Gateway limitations, the lambda authorizer cannot access the payload of the incoming request. 

Another option would be to skip the API gatway authorization part and use the API gateway to proxy the request to lambda, then from lambda authenticate the webhook and forward the request to the Jenkins instance. One could also fron the API Gateway with an AWS WAF. But all these come with increased costs.

Unfortunately, the AWS WAF cannot yet protect AWS Lambda urls directly for now...
