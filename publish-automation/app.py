"""ThreatConnect Exchange Playbook App"""

import json

from tcex.api.tc.v2.batch.batch import Batch

from helper.publish import PublishError, publish
from playbook_app import PlaybookApp


class App(PlaybookApp):
    """Copy a group into one or more owners."""

    def run(self):
        """Publish the group described by the request JSON."""
        try:
            self._results = publish(
                self.tcex.session.tc,
                self.tcex.api.tc.v2.batch,
                self.in_.request_json,
                Batch.generate_xid2,
            )
        except PublishError as ex:
            self.tcex.exit.exit(1, str(ex))
        self.log.info('Publish complete: %s', self._results)

    def write_output(self):
        """Write per-owner results (existing or published)."""
        self.out.string('publish.result', json.dumps(self._results))
