"""App Inputs"""

from tcex.input.field_type import Integer, String, Sensitive
from tcex.input.input import Input
from tcex.input.model.app_organization_model import AppOrganizationModel


class AppBaseModel(AppOrganizationModel):
    """Base model for the App containing any common inputs."""

    tc_owner: String
    rf_api_token: Sensitive

    # Max number of pages to process during the import run.
    batch_limit: Integer = Integer(50)
    # Mode selector:
    # - empty since_date => initial backfill behavior
    # - populated since_date => incremental behavior (timestamp > since_date)
    since_date: String = String("")
    tc_confidence: String = String("50")
    tc_threat_rating: String = String("3")


class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize class properties."""
        self.inputs = inputs

    def update_inputs(self):
        """Add custom App models to inputs. Validation will run at the same time."""
        self.inputs.add_model(AppBaseModel)
