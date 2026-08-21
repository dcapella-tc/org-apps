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
            if "exclusion list" not in str(data).lower():
                print(data)
                self.tcex.exit.exit(1, "See output log for more details...")
            return {}

        return data

    def run(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        indicators = []
        url = '/v3/indicators'
        params = {
            'tql': self.in_.tql,
            'owner': self.in_.owner_name,
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
