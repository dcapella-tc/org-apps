"""ThreatConnect Job App"""

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)

from report_template import *


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)
        self.used_ids = []

    def setup(self):
        """Perform prep/setup logic."""

    def run(self):
        """Run main App logic."""
        
        self._build_html(CYBER_BREACH_AND_COMPROMISE_NEWS, CYBER_BREACH_AND_COMPROMISE_NEWS_KEYWORDS)
        # self._build_html(ELECTRICITY_INFORMATION_SHARING_AND_ANALYSIS_CENTER_E_ISAC_ALERTS_AND_ADVISORIES, ELECTRICITY_INFORMATION_SHARING_AND_ANALYSIS_CENTER_E_ISAC_ALERTS_AND_ADVISORIES_KEYWORDS)
        # self._build_html(CYBER_SECURITY_NEWS_RUSSIA_UKRAINE, CYBER_SECURITY_NEWS_RUSSIA_UKRAINE_KEYWORDS)
        # self._build_html(CYBER_SECURITY_NEWS_GENERAL, CYBER_SECURITY_NEWS_GENERAL_KEYWORDS)
        # self._build_html(CYBER_SECURITY_NEWS_GOVERNMENTS, CYBER_SECURITY_NEWS_GOVERNMENTS_KEYWORDS)
        # self._build_html(CYBER_SECURITY_NEWS_BUSINESSES, CYBER_SECURITY_NEWS_BUSINESSES_KEYWORDS)
        # self._build_html(MALWARE_BOTNET_CRYPTO_MINING_NEWS, MALWARE_BOTNET_CRYPTO_MINING_NEWS_KEYWORDS)
        # self._build_html(PHISHING_NEWS, PHISHING_NEWS_KEYWORDS)
        # self._build_html(PRODUCT_VULNERABILITY_NEWS, PRODUCT_VULNERABILITY_NEWS_KEYWORDS)
        # self._build_html(MOBILE_DEVICES, MOBILE_DEVICES_KEYWORDS)
    def _build_html(self, title: str, keywords: str):
        """Build the HTML report."""
        if self.used_ids:
            tql = f'dateAdded >= "{self.in_.last_run}" and {keywords} and id not in ({",".join(self.used_ids)})'
        else:
            tql = f'dateAdded >= "{self.in_.last_run}" and {keywords}'

        self.log.info(f'TQL: {tql}')

        groups = self.tcex.api.tc.v3.groups()

        # add one or more TQL filters
        groups.filter.tql = tql

        # iterate over results
        count = 0
        for group in groups:
            print(group.model.dict(exclude_none=True))
            count += 1
            if count >= int(self.in_.max_results):
                break
        