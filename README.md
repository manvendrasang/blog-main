# blog-main

AWS S3 Bucket Setup
> Create a AWS account
> Search for S3(scalable storage in the cloud)
> Click on create bucket(bucket name, select nearest region, uncheck block all public areas, i acknowledge, lastly click create bucket)
> click on your new bucket
> goto permissions to create a bucket policy and define cross-origin resource sharing
> Bucket Policy-click edit-click on policy generator-(Step-1)select S3 bucket type of policy-(Step-2)effect allow, principal use *, Actions choose(GetObject, PutObject), for the ARN number go back to the edit bucket policy AWS page copy and paste the bucket ARN, click on add statement-(Step-3)click on generate policy, copy the json document presented to you, paste that code on the edit policy page, if for some reason you are not allowed to save the policy, in the edit box where you pasted the json code look for Resource it should contain your ARN key, at the end of the key add this "/ *"(there is no space in between this).-click on save your policy would've been generated
> goto CORS and click edit- write down the following in the box-save changes

[
    {
        "AllowedHeaders": [
            "*"
        ],
        "AllowedMethods": [
            "PUT",
            "GET",
            "HEAD"
        ],
        "AllowedOrigins": [
            "*"
        ],
        "ExposedHeaders": []
    }
]

> after this goto server.js in server folder and uncomment the aws code
> then goto the aws website and search for IAM(Manage access to AWS resources)
> goto policies-create policy-in the services choose s3-actions allowed(GetObeject, PutObject)-under resources select specific and click on Add ARNs(paste the ARN, click on any object name)-Add ARNs-click on next-give policy name-create policy
> now goto Users in the same tab-create user-write a name-next-click on attach policies directly-search for the policy that you just created-check it-next-create user-click on the user just created-create access key-select other(you can select any option)-next-create access key, copy both the keys and paste it in .env