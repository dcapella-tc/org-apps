"""App Inputs"""

from tcex.input.field_type import Sensitive, String
from tcex.input.input import Input
from tcex.input.model.app_organization_model import AppOrganizationModel


class AppBaseModel(AppOrganizationModel):
    """Base model for the App containing any common inputs."""

    pir_id: String
    tc_owner: String
    polarity_base_url: String
    polarity_api_key: Sensitive
    result_limit: String = String('1000')


class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize class properties."""
        self.inputs = inputs

    def update_inputs(self):
        """Add custom App models to inputs. Validation will run at the same time."""
        self.inputs.add_model(AppBaseModel)
