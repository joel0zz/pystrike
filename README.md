# Welcome to Pystrike

This is a CLI tool to easily interact with the CrowdStrike API 

# Install
pip install --editable .  
Make sure you have credential_manager in .aws/credentials - This will be used for securely retrieving the API key for auth to CS - this should have permissions for KMS.  
You will also need to make sure you have uploaded the CS API creds to an s3 bucket of your choice, just make sure it's called "cs_auth".    

# Usage
run 'pystrike' in the CLI.