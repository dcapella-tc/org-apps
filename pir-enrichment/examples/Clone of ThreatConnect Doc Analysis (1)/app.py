"""ThreatConnect Exchange Playbook App"""

# standard library
import json
import re

# third-party
import requests.auth

# first-party
from playbook_app import PlaybookApp


class CALAuth(requests.auth.AuthBase):  # pylint: disable=too-few-public-methods
    """Token-based auth for CAL."""

    def __init__(self, token: str, timestamp: int):
        """Token authentication for CAL.

        Args:
            token: authorization token from CAL.
            timestamp: token timestamp.
        """
        self.token = token
        self.timestamp = timestamp
        self.auto_ingest = self.in_.auto_ingest

    def __call__(self, r: requests.PreparedRequest):
        """Add authorization headers to a CAL request.

        Args:
            r: the request to be sent.

        Returns:
            Request with CAL auth headers added.
        """
        r.headers['Authorization'] = self.token
        r.headers['Timestamp'] = str(self.timestamp)
        return r


class App(PlaybookApp):
    """ThreatConnect Exchange App"""

    def categorize_hashes(self):
        md5_list = []
        sha1_list = []
        sha256_list = []

        # Define regex patterns for MD5, SHA1, and SHA256 (all are hexadecimal)
        md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
        sha1_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
        sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')

        for hash_value in self.file_array:
            if md5_pattern.match(hash_value):
                md5_list.append(hash_value)
            elif sha1_pattern.match(hash_value):
                sha1_list.append(hash_value)
            elif sha256_pattern.match(hash_value):
                sha256_list.append(hash_value)

        return md5_list, sha1_list, sha256_list

    def analyze_document(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.session = self.tcex.session.external
        self.session.log_curl = True
        self.session.base_url = 'https://cal.threatconnect.com/'
        self.session.auth = CALAuth(self.in_.tc_cal_token.value, self.in_.tc_cal_timestamp)

        doc = self.in_.document
        if not isinstance(doc, str):
            try:
                doc = doc.decode('utf-8')
            except Exception as e:
                self.tcex.log.critical(f'Failed to decode document: {e}')

        self.doc_length = len(doc)
        doc = doc[:100000]
        self.input_truncated = len(doc) > 100000

        features_mapping = {
            'Alias Extraction': 'alias',
            'IOC Extraction': 'ioc',
            'AI MITRE ATT&CK Classification': 'attack',
            'AI NAICS Industry Classification': 'textindustry',
            'AI Summary Generation': 'textsummarize',
        }

        additional_features_mapping = {
            'Zero Day (topic detector)': 'zeroday',
            'Zero Day Summary (includes topic detector)': 'zerodaysummary',
        }
        selected_apps = [features_mapping[feature] for feature in self.in_.features]
        apps_value = ','.join(selected_apps)
        # self.tcex.log.debug(f'Selected CAL apps: {apps_value}')
        if (
            self.in_.additional_features is not None
            and self.in_.additional_features in additional_features_mapping
        ):
            apps_value = f'{apps_value},{additional_features_mapping[self.in_.additional_features]}'
            # self.tcex.log.debug(f'Including additional CAL app: {apps_value}')
        params = {
            'source': 'playbooks',
            'apps': apps_value,
            'output': 'clean',
        }

        self.tcex.log.debug(f'Params for CAL request: {params}')

        documents = [
            {
                'name': 'Playbook Document',
                'text': doc,
                'sourceId': 'http://threatconnect.com/playbooks',
                'shareable': 1,
            }
        ]

        try:
            req = self.session.post('/helix/document/v1/analyze', params=params, json=documents)
            self.tcex.log.debug(f'CAL response: {req.text}')
            if req.status_code == 429:
                self.tcex.exit.exit(
                    1, 'Too many requests in the last 24 hours. Please try again later!'
                )

            req.raise_for_status()
            self.response = req.json()
            self.app_data = self.response[0].get('appData', [{}])
        except Exception as e:
            self.app_data = [{}]
            if self.in_.fail_on_error:
                self.tcex.exit.exit(1, f'Failed to analyze document: {e}')

        self.file_array = [
            row.get('uniqueId', None)
            for row in self.app_data
            if 'uniqueId' in row and row.get('indicatorType') == 'file'
        ]

        self.md5, self.sha1, self.sha256 = self.categorize_hashes()
        self.doc_summary = None
        self.text_industry = []
        self.doc_summary_bullets = None

        for row in self.app_data:
            app = row.get('app')
            if app == 'TextSummarizer':
                self.doc_summary = row.get('summary')
                self.doc_summary_bullets = row.get('bullets', [])
            elif app == 'TextIndustrializer':
                industry = row.get('industry', [])
                self.text_industry = [industry] if isinstance(industry, str) else (industry or [])

        

    def set_variable_with_count(self, name, array):
        """Set a variable with count."""

        self.tcex.log.debug(f'Setting variable {name}')
        self.out.variable(name, array)
        size = len(array) if array is not None else 0
        self.tcex.log.debug(f'Setting variable {name}.count with count {len(array)}')
        self.out.variable(f'{name}.count', size)

    

    def write_output(self):
        """Write the Playbook output variables.

        This method should be overridden with the output variables defined in the install.json
        configuration file.
        """
        # app data result keys: AliasExtractor, IOCExtractor, AttackLabeler,
        # TextIndustrializer, TextSummarizer
        # self.tcex.log.debug(f"Raw json: {json.dumps(self.response, indent=4)}")
        self.out.variable('tc.json.raw', json.dumps(self.response))
        self.out.variable('tc.summary', self.doc_summary)
        self.out.variable('tc.summary.bullets', self.doc_summary_bullets)
        self.out.variable('tc.naics.codes', self.text_industry)
        self.out.variable('tc.input_truncated', str(self.input_truncated))
        self.out.variable('tc.input_length', self.doc_length)

        # process md5, sha1, sha256 separately
        self.set_variable_with_count('tc.parsed.md5_array', self.md5)
        self.set_variable_with_count('tc.parsed.sha1_array', self.sha1)
        self.set_variable_with_count('tc.parsed.sha256_array', self.sha256)

        indicator_mappings = {
            'address': 'tc.parsed.address_array',
            'emailaddress': 'tc.parsed.email_address_array',
            'file': 'tc.parsed.file_array',
            'url': 'tc.parsed.url_array',
            'host': 'tc.parsed.host_array',
            'asn': 'tc.parsed.asn_array',
            'cidr': 'tc.parsed.cidr_array',
            'emailSubject': 'tc.parsed.email_subject_array',
            'hashtag': 'tc.parsed.hashtag_array',
            'mutex': 'tc.parsed.mutex_array',
            'registryKey': 'tc.parsed.registry_key_array',
            'userAgent': 'tc.parsed.user_agent_array',
        }

        object_mappings = {
            ('vulnerability', 'objectId'): 'tc.parsed.cve_array',
            ('malware', 'description'): 'tc.parsed.malware_descriptions',
            ('malware', 'displayName'): 'tc.parsed.malware_names',
            ('attack pattern', 'objectId'): 'tc.parsed.attack_pattern_tags',
            ('attack pattern', 'description'): 'tc.parsed.attack_pattern_descriptions',
            ('intrusion set', 'displayName'): 'tc.parsed.intrusion_set_names',
            ('intrusion set', 'description'): 'tc.parsed.intrusion_set_descriptions',
            ('tactic', 'displayName'): 'tc.parsed.tactic_names',
            ('tactic', 'description'): 'tc.parsed.tactic_descriptions',
            ('tools', 'displayName'): 'tc.parsed.tools_names',
            ('tools', 'description'): 'tc.parsed.tools_descriptions',
            ('course of action', 'displayName'): 'tc.parsed.course_of_action_names',
            ('course of action', 'description'): 'tc.parsed.course_of_action_descriptions',
        }

        if self.in_.additional_features not in [None, 'None']:
            topic_values = [
                row.get('topic')
                for row in self.app_data
                if row.get('app') == 'ZeroDayAnalyzer' and 'topic' in row
            ]
            self.tcex.log.debug(f'Zero Day topics: {topic_values}')
            self.set_variable_with_count('tc.parsed.zeroday.topic', topic_values[0])

            summary_values = [
                row.get('summary')
                for row in self.app_data
                if row.get('app') == 'TextSummarizer' and 'summary' in row
            ]
            self.set_variable_with_count(
                'tc.parsed.zeroday.summary',
                summary_values[1] if len(summary_values) > 1 else summary_values[0],
            )

        for indicator_type, variable_name in indicator_mappings.items():
            values = [
                row.get('uniqueId')
                for row in self.app_data
                if row.get('indicatorType') == indicator_type and 'uniqueId' in row
            ]
            self.set_variable_with_count(variable_name, values)

        for (object_type, field_name), variable_name in object_mappings.items():
            values = [
                row.get(field_name)
                for row in self.app_data
                if row.get('objectType') == object_type
                and field_name in row
                and row.get(field_name) is not None
            ]
            self.set_variable_with_count(variable_name, values)

        converted_tags = [
            self.tcex.api.tc.v3.mitre_tags.get_by_id(row.get('objectId'))
            for row in self.app_data
            if row.get('objectType') == 'attack pattern'
            and 'objectId' in row
            and self.tcex.api.tc.v3.mitre_tags.get_by_id(row.get('objectId')) is not None
        ]
        self.set_variable_with_count('tc.parsed.attack_pattern_tags', converted_tags)

        unique_datasets = {
            (
                'attack pattern',
                'objectId',
                'AliasExtractor',
            ): 'tc.parsed.attack_pattern_tags.aliasextractor',
            (
                'attack pattern',
                'description',
                'AliasExtractor',
            ): 'tc.parsed.attack_pattern_descriptions.aliasextractor',
            (
                'attack pattern',
                'objectId',
                'AttackLabeler',
            ): 'tc.parsed.attack_pattern_tags.attackanalyzer',
            (
                'attack pattern',
                'description',
                'AttackLabeler',
            ): 'tc.parsed.attack_pattern_descriptions.attackanalyzer',
        }

        for (object_type, field_name, app), variable_name in unique_datasets.items():
            if field_name == 'description':
                values = [
                    row.get(field_name)
                    for row in self.app_data
                    if row.get('objectType') == object_type
                    and field_name in row
                    and row.get('app') == app
                ]
                self.set_variable_with_count(variable_name, values)
            elif field_name == 'objectId':
                converted_tags = [
                    self.tcex.api.tc.v3.mitre_tags.get_by_id(row.get(field_name))
                    for row in self.app_data
                    if row.get('objectType') == object_type
                    and field_name in row
                    and row.get('app') == app
                ]
                self.set_variable_with_count(variable_name, converted_tags)
