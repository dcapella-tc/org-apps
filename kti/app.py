"""ThreatConnect Job App"""

import json
import re
from pathlib import Path

from tcex import TcEx
from tcex.exit import ExitCode

from job_app import JobApp  # Import default Job App Class (Required)


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties."""
        super().__init__(_tcex)

        # properties
        # self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)

    def setup(self):
        """Perform prep/setup logic."""
        # setting the base url allow for subsequent API call
        # to be made by only providing the API endpoint/path.
        # self.tcex.session.external.base_url = 'https://feodotracker.abuse.ch'

        # Tor Nodes
        # flags: "flag:{flag name}"
        # name: tags

    def run(self):
        """Run main App logic."""
        self.batch = self.tcex.api.tc.v2.batch(self.in_.tc_owner)
        self._load_tor_nodes()
        self._batch_submit()

    def _load_tor_nodes(self):
        """Load Tor nodes from file."""
        tor_nodes_path = (
            Path(__file__).resolve().parent
            / "examples"
            / "Known Tor Infrastructure (1).json"
        )
        if not tor_nodes_path.is_file():
            self.tcex.log.error("Tor nodes file not found: %s", tor_nodes_path)
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f"Tor nodes file not found: {tor_nodes_path}",
            )

        try:
            with tor_nodes_path.open(encoding="utf-8") as f:
                tor_nodes = json.load(f)
        except json.JSONDecodeError as ex:
            self.tcex.log.error("Invalid JSON in Tor nodes file: %s", ex)
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                f"Invalid JSON in Tor nodes file: {ex}",
            )

        if not isinstance(tor_nodes, list):
            self.tcex.log.error(
                "Tor nodes file must contain a JSON array, got %s",
                type(tor_nodes).__name__,
            )
            self.tcex.exit.exit(
                ExitCode.FAILURE,
                "Tor nodes file must contain a JSON array.",
            )

        self.tcex.log.info("Loaded %d Tor node records from %s", len(tor_nodes), tor_nodes_path)

        for node in tor_nodes:
            if not isinstance(node, dict):
                self.tcex.log.warning("Skipping non-object entry: %r", node)
                continue
            ip = node.get("ip")
            if not ip:
                self.tcex.log.warning("Skipping entry without ip: %r", node)
                continue
            ioc = {
                "value": ip,
                "flags": node.get("flags"),
                "name": node.get("name"),
            }
            self._batch_save_ioc(ioc)

    def _batch_submit(self):
        """Submit batch job and handle errors."""
        batch_response = self.batch.submit_all()
        self.tcex.log.debug(f"batch_response: {batch_response}")
        self.batch.close()

        errors = []
        success = 0
        for item in batch_response:
            errors.extend(item.get('errors', []))
            success += item.get('successCount', 0)
        if errors:
            known_errors = []
            self.tcex.log.error('App.run: batch submission failed with %d errors', len(errors))

            error_count = 0
            for error in errors:
                error_count += 1
                if error_count == 100: break
                error_reason = error.get('errorReason', '')
                if 'Found duplicate indicator in batch job file' in error_reason:
                    if 'Found duplicate indicator in batch job file' in known_errors:
                        continue
                    known_error = 'Found duplicate indicator in batch job file'
                else:
                    try:
                        error_reason = error_reason.split('is not valid. ')[1]
                    except:
                        pass
                    known_error = re.sub(r"'[^']*'", '', error_reason).strip()
                    if known_error in known_errors:
                        continue
                known_errors.append(known_error)
                self.tcex.log.error('App.run: batch submission error: %s', error)
        else:
            self.tcex.log.info("No errors found.")

        if success:
            self.tcex.log.info('App.run: batch submission successful with %d items', success)
        else:
            self.tcex.log.warning("No successes found.")


    def _batch_save_ioc(self, ioc):
        """Save IOC to batch."""
        # init
        indicator = self.batch.indicator("Address", ioc['value'], rating=self.in_.rating, confidence=self.in_.confidence)
        
        # tags
        indicator.tag("Tor Node")
        if ioc.get('flags'):
            tag = f'flag:{ioc["flags"]}'
            indicator.tag(tag)
        if ioc.get('name'):
            tag = f'name:{ioc["name"]}'
            indicator.tag(tag)

        self.batch.save(indicator)




        # with self.tcex.session.external as s:
            # https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json
            # r = s.get('/downloads/ipblocklist_recommended.json')

            # if r.ok:
            #     ti_data = r.json()

                # Example JSON
                # {
                #   "ip_address": "178.128.23.9",
                #   "port": 4125,
                #   "status": "online",
                #   "hostname": null,
                #   "as_number": 14061,
                #   "as_name": "DIGITALOCEAN-ASN",
                #   "country": "SG",
                #   "first_seen": "2021-05-16 19:49:33",
                #   "last_online": "2023-04-29",
                #   "malware": "Dridex"
                # }

                # for ti in ti_data:
                    # create batch entry
        #             ip_address = ti['ip_address']
        #             address = self.batch.address(ip_address, rating='4.0', confidence='100')

        #             # map first seen to "First Seen" attribute
        #             first_seen = ti.get('first_seen')
        #             if first_seen:
        #                 first_seen = self.tcex.util.any_to_datetime(first_seen).strftime(
        #                     '%Y-%m-%dT%H:%M:%SZ'
        #                 )
        #                 address.attribute('First Seen', first_seen)

        #             # map last online to "Last Seen" attribute
        #             last_online = ti.get('last_online')
        #             if last_online:
        #                 last_online = self.tcex.util.any_to_datetime(last_online).strftime(
        #                     '%Y-%m-%dT%H:%M:%SZ'
        #                 )
        #                 address.attribute('Last Seen', last_online)

        #             # map port to "Port" attribute
        #             port = ti.get('port')
        #             if port:
        #                 address.attribute('Port', port)

        #             # map malware to "Malware" tag
        #             malware = ti.get('malware')
        #             if malware:
        #                 address.tag(malware)

        #             # optionally save object to disk to save on memory usage
        #             self.batch.save(address)
        #     else:
        #         self.tcex.exit.exit(ExitCode.SUCCESS, 'Failed to download data.')

        # # submit batch job
        # batch_status = self.batch.submit_all()
        # self.log.info(f'batch-status={batch_status}')

        # self.exit_message = 'Downloaded data and create batch job.'
