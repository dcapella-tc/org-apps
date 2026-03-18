"""App Inputs"""

from tcex.input.field_type import Integer, String
from tcex.input.input import Input
from tcex.input.model.app_organization_model import AppOrganizationModel


class AppBaseModel(AppOrganizationModel):
    """Base model for the App containing any common inputs."""

    tc_owner: String
    # If true, this execution performs a one-time import from newest->oldest.
    initial_run: bool = False
    # Max number of pages to process during the initial import.
    batch_limit: Integer = Integer(50)
    # For non-initial run: fetch records with timestamp after this date (ISO datetime or date). Optional.
    since_date: String = ""


class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize class properties."""
        self.inputs = inputs

    def update_inputs(self):
        """Add custom App models to inputs. Validation will run at the same time."""
        self.inputs.add_model(AppBaseModel)
