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