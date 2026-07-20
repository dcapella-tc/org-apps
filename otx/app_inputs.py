"""App Inputs"""

from tcex.input.field_type import Sensitive, String
from tcex.input.input import Input
from tcex.input.model.app_organization_model import AppOrganizationModel


class AppBaseModel(AppOrganizationModel):
    """Base model for the App containing any common inputs."""

    tc_owner: String
    # Optional locally: leave empty and set otx_api_key in .env for tcex run.
    # Required on the ThreatConnect platform via install.json.
    otx_api_key: Sensitive = Sensitive('')
    # Optional ISO datetime; empty string uses the default 24-hour lookback.
    last_modified: String = String('')


class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize class properties."""
        self.inputs = inputs

    def update_inputs(self):
        """Add custom App models to inputs. Validation will run at the same time."""
        self.inputs.add_model(AppBaseModel)
