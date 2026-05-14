"""ThreatConnect Exchange Job App."""

from pathlib import Path

from job_app import JobApp

OUTPUT_CSV = 'data.csv'


class App(JobApp):
    """ThreatConnect Exchange App."""

    def run(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        # publishOutFiles docs mention tc_output_path; TcEx PathModel uses tc_out_path.
        out_dir = Path(self.in_.tc_out_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / OUTPUT_CSV).write_text(self.in_.csv_data, encoding='utf-8')
        self.log.info('feature=app, event=wrote-csv, path=%s', out_dir / OUTPUT_CSV)
