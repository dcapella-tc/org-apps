"""ThreatConnect Exchange Job App."""

from helper.indicators import fetch_enriched_summaries, fetch_for_pir, has_enrichment_tag
from helper.polarity import (
    build_auth_headers,
    list_integrations,
    lookup_all,
    matching_ids,
)
from helper.type_map import map_polarity_type
from helper.writeback import add_enrichment_tag, set_description
from job_app import JobApp


class App(JobApp):
    """ThreatConnect Exchange App."""

    def setup(self):
        """Configure Polarity base URL on the external session."""
        self.tcex.session.external.base_url = str(self.in_.polarity_base_url).rstrip('/')

    def run(self):
        """Enrich PIR-associated IOCs via Polarity."""
        pir_id = str(self.in_.pir_id)
        owner = str(self.in_.tc_owner)
        result_limit = int(str(self.in_.result_limit) or '1000')
        api_key = self.in_.polarity_api_key.value
        headers = build_auth_headers(api_key)

        enriched_summaries = fetch_enriched_summaries(
            self.tcex.session.tc,
            owner,
            result_limit=result_limit,
        )
        self.log.info(
            'Found %s already-enriched summar(ies) in owner %s',
            len(enriched_summaries),
            owner,
        )

        iocs = fetch_for_pir(
            self.tcex.session.tc,
            pir_id,
            owner=owner,
            result_limit=result_limit,
            skip_summaries=enriched_summaries,
        )
        self.log.info('Fetched %s indicator(s) for PIR %s', len(iocs), pir_id)

        with self.tcex.session.external as polarity_session:
            integrations = list_integrations(polarity_session, headers)
            enriched = skipped = failed = 0

            for ioc in iocs:
                if has_enrichment_tag(ioc):
                    skipped += 1
                    continue

                polarity_type = map_polarity_type(ioc)
                if not polarity_type:
                    skipped += 1
                    continue

                summary = str(ioc.get('summary') or '')
                integration_ids = matching_ids(integrations, polarity_type)
                content = lookup_all(
                    polarity_session,
                    headers,
                    integration_ids,
                    summary,
                    polarity_type,
                    log=self.log,
                )
                if not content:
                    failed += 1
                    continue

                indicator_id = ioc['id']
                set_description(self.tcex.session.tc, indicator_id, content)
                add_enrichment_tag(self.tcex.session.tc, indicator_id, ioc)
                enriched += 1

        self.exit_message = (
            f'PIR {pir_id}: enriched={enriched} skipped={skipped} failed={failed} '
            f'total={len(iocs)}'
        )
