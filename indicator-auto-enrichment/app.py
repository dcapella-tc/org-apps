"""ThreatConnect Exchange Job App."""

from job_app import JobApp


class App(JobApp):
    """ThreatConnect Exchange App."""

    def _request(self, req):
        self.tcex.log.info(f'Making {req.get("method")} request...')
        self.tcex.log.debug(str(req))

        response = self.tcex.session.tc.request(**req)
        try:
            data = response.json()
        except ValueError:
            data = {"message": response.text}
        if not response.ok:
            if "exclusion list" in str(data).lower():
                return {}
            messages = data.get('messages') if isinstance(data, dict) else None
            if (
                isinstance(messages, list)
                and messages
                and all('No enrichment data found' in str(message) for message in messages)
            ):
                count = data.get('unableEnrich', len(messages))
                self.tcex.log.info(f'Enrichment returned no data for {count} indicators')
                return data
            print(data)
            self.tcex.exit.exit(1, "See output log for more details...")

        return data

    def run(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        tql = (self.in_.tql or '').strip()
        if not tql:
            tql = 'vtLastUpdated is null'
        elif 'vtLastUpdated' not in tql:
            tql = f'({tql}) and (vtLastUpdated is null)'

        indicators = []
        url = '/v3/indicators'
        params = {
            'tql': tql,
            'resultLimit': 10000,
        }
        while url:
            data = self._request({'method': 'GET', 'url': url, 'params': params})
            indicators.extend(data.get('data') or [])
            url = data.get('next')
            params = {}

        self.tcex.log.info(f'Retrieved {len(indicators)} indicators')

        batch_size = 500
        for i in range(0, len(indicators), batch_size):
            batch = indicators[i:i + batch_size]
            self.tcex.log.info(f'Enriching batch {i // batch_size + 1} ({len(batch)} indicators)')
            self._request({
                'method': 'POST',
                'url': '/v3/indicators/enrich',
                'params': {'type': 'VirusTotalV3'},
                'json': {'data': [{'id': ind['id']} for ind in batch]},
            })
