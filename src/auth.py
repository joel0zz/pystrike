from falconpy import api_complete as FalconSDK

def cs_auth(client_id, client_secret):
    try:
        falcon = FalconSDK.APIHarness(creds={
            'client_id': client_id,
            'client_secret': client_secret
        })
    except Exception:
        print('[-] Access token could not be generated, please check id/secret')
        exit()
    if falcon.authenticate():
        print("[+] Authenticated to Crowdstrike Falcon API")
        return falcon


  