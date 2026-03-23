"""ThreatConnect Exchange Job App."""

from job_app import JobApp


class App(JobApp):
    """ThreatConnect Exchange App."""

    def run(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """

    def _get_groups(self):
        """Get the groups from the ThreatConnect API."""
        groups = self.tcex.api.tc.v3.groups()

        # add one or more TQL filters
        groups.filter.tql = 'hasThreatActorProfile()'

        # iterate over results
        for group in groups:
            print(group.model.dict(exclude_none=True))
            break