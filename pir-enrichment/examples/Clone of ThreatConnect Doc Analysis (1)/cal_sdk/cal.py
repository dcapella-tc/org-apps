# -*- coding: utf-8 -*-
"""CAL API client including authentication."""
# standard library
import base64
import hashlib
import hmac
import time
from typing import Dict, List

# third-party
from requests import PreparedRequest
from requests.auth import AuthBase
from tcex.requests_external import ExternalSession

# first-party
from cal_sdk.cal_types import CALDetailsResponse


class CALAuth(AuthBase):
    """Token-based auth for CAL."""

    def __init__(self, token: str, timestamp: str):
        """Token authentication for CAL.

        Args:
            token: authorization token from CAL.
            timestamp: token timestamp.
        """
        self.token = token
        self.timestamp = timestamp

    def __call__(self, r: PreparedRequest):
        """Add authorization headers to a CAL request.

        Args:
            r: the request to be sent.

        Returns:
            Request with CAL auth headers added.
        """
        r.headers['Authorization'] = self.token
        r.headers['Timestamp'] = self.timestamp
        return r


def create_cal_token_and_timestamp(license_key: str, instance_id: str) -> CALAuth:
    """Create a CALAuth object from TC license info.

    Both of the arguments can be found in a TC license file.
    Args:
        license_key: License key from license xml file.
        instance_id: Instance ID from license xml file.

    Returns:
        CALAuth object.
    """
    tc_cal_timestamp = str(int(time.time()))

    signature = f'{instance_id}:{tc_cal_timestamp}'
    hmac_signature = hmac.new(
        license_key.encode(), signature.encode(), digestmod=hashlib.sha256
    ).digest()
    tc_cal_token = f'HELIXTOKEN {signature}:{base64.b64encode(hmac_signature).decode()}'

    return CALAuth(tc_cal_token, tc_cal_timestamp)


class CAL:
    """Client for CAL API."""

    def __init__(
        self,
        cal_host: str,
        cal_token: str,
        cal_timestamp: str,
        session: ExternalSession,
        verify_ssl=True,
    ):
        """SDK for the CAL API.

        Args:
            cal_host: CAL instance host.
            cal_token: authorization token from CAL.
            cal_timestamp: token timestamp.
            session: Session to use to communicate with CAL.
            verify_ssl: whether or not to verify CAL's SSL certificate.
        """
        self._session = session
        self._session.base_url = f'https://{cal_host}'
        self._session.verify = verify_ssl
        self._session.auth = CALAuth(cal_token, cal_timestamp)

    def get_details(self, indicators: List[Dict[str, str]]) -> List[CALDetailsResponse]:
        """Send indicators to CAL to get details.

        Args:
            indicators: Indicators to send to cal, expected to be in the format:
                {
                    'uniqueId': '127.0.0.1',
                    'indicatorType': 'Address'
                }

        Returns:
            A list of CALDetailResponses.

        Raises:
            HTTPError on a non-successful response from CAL.
        """
        response = self._session.post(
            '/helix/indicators/v4/details?source=playbooks',
            headers={'Content-Type': 'application/json', 'Cache-Control': 'no-cache'},
            json=indicators,
        )
        response.raise_for_status()

        return [CALDetailsResponse(d) for d in response.json()]
