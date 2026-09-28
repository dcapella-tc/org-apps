"""App Inputs"""
# pyright: reportGeneralTypeIssues=false

from tcex.input.field_type import String
from tcex.input.input import Input
from tcex.input.model.app_playbook_model import AppPlaybookModel


class AppBaseModel(AppPlaybookModel):
    """Base model for the App containing any common inputs."""

    request_json: String


class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize instance properties."""
        self.inputs = inputs

    def update_inputs(self):
        """Add custom App model to inputs.

        Input will be validated when the model is added and any exceptions will
        cause the App to exit with a status code of 1.
        """
        self.inputs.add_model(AppBaseModel)
