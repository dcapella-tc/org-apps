"""ThreatConnect Job App"""

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

    def setup(self):
        """Perform prep/setup logic."""

    def run(self):
        """Run main App logic."""
        