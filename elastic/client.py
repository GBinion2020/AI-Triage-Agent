#This file is to gain an intial an established connection to the Elastic SIEM,
#With this file we will not need to gain access everytime we perform queries in our session. 

import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ElasticClient:
    def __init__(self):
        self.base_url = os.getenv("ELASTIC_BASE_URL")
        api_key = os.getenv("ELASTIC_API_KEY")

        if not self.base_url or not api_key:
            raise ValueError("ELASTIC_BASE_URL and ELASTIC_API_KEY must be set")

        self.base_url = self.base_url.rstrip("/")

        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"ApiKey {api_key}",
            "kbn-xsrf": "true"
        }

    def get(self, endpoint, params=None):
        url = f"{self.base_url}{endpoint}"

        response = requests.get(
            url,
            headers=self.headers,
            params=params,
            verify=False,
            timeout=30
        )

        response.raise_for_status()
        return response.json()

    def post(self, endpoint, payload):
        url = f"{self.base_url}{endpoint}"

        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            verify=False,
            timeout=30
        )

        response.raise_for_status()
        return response.json()
